// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zarf-dev/zarf/src/api/v1alpha1"
	"github.com/zarf-dev/zarf/src/api/v1beta1"
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

func TestParsePackageSingleDocumentPreambles(t *testing.T) {
	for _, apiVersion := range []string{"", v1alpha1.APIVersion, v1beta1.APIVersion} {
		for _, prefix := range []string{"# license\n---\n", "%YAML 1.2\n---\n", "# license\n%YAML 1.2\n---\n"} {
			t.Run(apiVersion+"/"+prefix, func(t *testing.T) {
				source := prefix
				if apiVersion != "" {
					source += "apiVersion: " + apiVersion + "\n"
				}
				source += "kind: ZarfPackageConfig\nmetadata: {name: example}\n...\n# trailing comment\n"
				pkg, err := ParsePackage([]byte(source))
				require.NoError(t, err)
				if apiVersion == v1beta1.APIVersion {
					require.IsType(t, &v1beta1.Package{}, pkg)
					require.Equal(t, "example", pkg.(*v1beta1.Package).Metadata.Name)
				} else {
					require.IsType(t, &v1alpha1.ZarfPackage{}, pkg)
					require.Equal(t, "example", pkg.(*v1alpha1.ZarfPackage).Metadata.Name)
				}
			})
		}
	}
}

func TestGetPackageNameRejectsUnsupportedSources(t *testing.T) {
	for _, test := range []struct{ name, source, wantError string }{
		{"component", "apiVersion: zarf.dev/v1beta1\nkind: ZarfComponentConfig\nmetadata: {name: component}\ncomponent: {}\n", "expected a Zarf package"},
		{"multiple documents", "apiVersion: zarf.dev/v1alpha1\nmetadata: {name: alpha}\n---\napiVersion: zarf.dev/v1beta1\nmetadata: {name: beta}\n", "single Zarf package source document"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			require.NoError(t, os.WriteFile("zarf.yaml", []byte(test.source), 0o600))
			_, err := GetPackageName()
			require.ErrorContains(t, err, test.wantError)
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
