// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetPackageName(t *testing.T) {
	for _, apiVersion := range []string{"", "zarf.dev/v1alpha1", "zarf.dev/v1beta1"} {
		t.Run(apiVersion, func(t *testing.T) {
			t.Chdir(t.TempDir())
			source := "kind: ZarfPackageConfig\nmetadata:\n  name: example\n"
			if apiVersion != "" {
				source = "apiVersion: " + apiVersion + "\n" + source
			}
			if apiVersion == "zarf.dev/v1beta1" {
				source += `components:
  - name: app
    charts:
      - name: app
        valuesFiles:
          - path: values.yaml.tmpl
            enableTemplating: true
`
			}
			require.NoError(t, os.WriteFile("zarf.yaml", []byte(source), 0600))
			name, err := GetPackageName()
			require.NoError(t, err)
			require.Equal(t, "example", name)
		})
	}
}

func TestParsePackageChecksAPITypes(t *testing.T) {
	for _, source := range []string{
		"apiVersion: unsupported\nmetadata:\n  name: example\n",
		"apiVersion: zarf.dev/v1beta1\ncomponents:\n  - name: app\n    images: [example.com/app:1]\n",
		"apiVersion: zarf.dev/v1alpha1\ncomponents:\n  - name: app\n    images: [{name: 'example.com/app:1'}]\n",
	} {
		_, err := ParsePackage([]byte(source))
		require.Error(t, err)
	}
}
