// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFetchPublishedPackageFlavor(t *testing.T) {
	for _, flavor := range []string{"", "upstream"} {
		for _, apiVersion := range []string{"zarf.dev/v1alpha1", "zarf.dev/v1beta1"} {
			t.Run(flavor+"/"+apiVersion, func(t *testing.T) {
				definition := fmt.Sprintf("apiVersion: %s\nkind: ZarfPackageConfig\nmetadata: {name: app}\nbuild: {architecture: amd64, flavor: %q}\n", apiVersion, flavor)
				if apiVersion == "zarf.dev/v1beta1" {
					definition = "apiVersion: zarf.dev/v1alpha1\nkind: ZarfPackageConfig\nmetadata: {name: app}\nbuild: {flavor: " + fmt.Sprintf("%q", flavor) + "}\n---\n" + definition
				}
				digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(definition)))
				manifest, err := json.Marshal(ImageManifest{Layers: []Layer{{Digest: digest, Annotations: map[string]string{"org.opencontainers.image.title": "zarf.yaml"}}}})
				require.NoError(t, err)
				mockSBOMRegistry(t, map[string][]byte{"manifests/v1": manifest, "blobs/" + digest: []byte(definition)})
				got, err := FetchPackageFlavor("test", "app", "v1")
				require.NoError(t, err)
				require.Equal(t, flavor, got)
			})
		}
	}
}

func TestPublishedPackageFlavorRequiresBuildMetadata(t *testing.T) {
	_, err := readPackageFlavor([]byte("kind: ZarfPackageConfig\nmetadata: {name: app}\n"))
	require.ErrorContains(t, err, "build metadata")
	flavor, err := readPackageFlavor([]byte("kind: ZarfPackageConfig\nmetadata: {name: app}\nbuild: {architecture: amd64}\n"))
	require.NoError(t, err)
	require.Empty(t, flavor)
	_, err = readPackageFlavor([]byte("kind: ZarfPackageConfig\nmetadata: {name: app}\nbuild: {flavor: upstream}\n---\napiVersion: zarf.dev/v1beta1\nkind: ZarfPackageConfig\nmetadata: {name: app}\nbuild: {flavor: unicorn}\n"))
	require.ErrorContains(t, err, "conflicting")
}
