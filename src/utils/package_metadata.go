// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"crypto/sha256"
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// FetchPackageFlavor reads the build flavor from the published package, independently of tag naming.
func FetchPackageFlavor(repoOwner, packageURL, tag string) (string, error) {
	base := "https://ghcr.io/v2/" + repoOwner + "/" + packageURL
	authToken := GetAuthToken()
	manifest, err := fetchPackageManifest(base, tag, authToken)
	if err != nil {
		return "", err
	}
	for _, layer := range manifest.Layers {
		if layer.Annotations["org.opencontainers.image.title"] != "zarf.yaml" {
			continue
		}
		data, err := getByteArray(base+"/blobs/"+layer.Digest, authToken, "application/octet-stream")
		if err != nil {
			return "", err
		}
		if layer.Digest != fmt.Sprintf("sha256:%x", sha256.Sum256(data)) {
			return "", fmt.Errorf("published Zarf definition digest mismatch")
		}
		return readPackageFlavor(data)
	}
	return "", fmt.Errorf("published package has no zarf.yaml layer")
}

func readPackageFlavor(data []byte) (string, error) {
	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return "", err
	}
	var flavor string
	found := false
	for _, doc := range file.Docs {
		if doc.Body == nil {
			continue
		}
		switch doc.Body.Type() {
		case ast.CommentType, ast.CommentGroupType, ast.DirectiveType:
			continue
		}
		var header struct {
			APIVersion string `yaml:"apiVersion"`
			Kind       string `yaml:"kind"`
			Metadata   struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Build *struct {
				Flavor string `yaml:"flavor"`
			} `yaml:"build"`
		}
		if err := yaml.NodeToValue(doc.Body, &header); err != nil {
			return "", err
		}
		switch header.APIVersion {
		case "", "zarf.dev/v1alpha1", "zarf.dev/v1beta1":
		default:
			continue
		}
		if header.Metadata.Name == "" || header.Build == nil ||
			(header.Kind != "ZarfPackageConfig" && header.Kind != "ZarfInitConfig") {
			return "", fmt.Errorf("published Zarf definition is missing package build metadata")
		}
		if found && flavor != header.Build.Flavor {
			return "", fmt.Errorf("published Zarf definitions have conflicting build flavors")
		}
		flavor = header.Build.Flavor
		found = true
	}
	if !found {
		return "", fmt.Errorf("published package has no supported Zarf definition")
	}
	return flavor, nil
}
