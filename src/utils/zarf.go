// Copyright 2024-2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"fmt"
	"os"

	goyaml "github.com/goccy/go-yaml"
	"github.com/zarf-dev/zarf/src/api/v1alpha1"
	"github.com/zarf-dev/zarf/src/api/v1beta1"
)

func GetPackageName() (string, error) {
	data, err := os.ReadFile("zarf.yaml")
	if err != nil {
		return "", err
	}
	pkg, err := ParsePackage(data)
	if err != nil {
		return "", err
	}
	switch pkg := pkg.(type) {
	case *v1alpha1.ZarfPackage:
		return pkg.Metadata.Name, nil
	case *v1beta1.Package:
		return pkg.Metadata.Name, nil
	default:
		return "", fmt.Errorf("unsupported Zarf package type %T", pkg)
	}
}

// ParsePackage decodes a definition using its declared Zarf API version.
func ParsePackage(data []byte) (any, error) {
	var header struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
	}
	if err := goyaml.Unmarshal(data, &header); err != nil {
		return nil, err
	}
	if header.Kind == string(v1beta1.ZarfComponentConfig) {
		return nil, fmt.Errorf("expected a Zarf package, got %q", header.Kind)
	}
	var pkg any
	switch header.APIVersion {
	case "", v1alpha1.APIVersion:
		pkg = &v1alpha1.ZarfPackage{}
	case v1beta1.APIVersion:
		pkg = &v1beta1.Package{}
	default:
		return nil, fmt.Errorf("unsupported Zarf apiVersion %q", header.APIVersion)
	}
	if err := goyaml.Unmarshal(data, pkg); err != nil {
		return nil, err
	}
	return pkg, nil
}
