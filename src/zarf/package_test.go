// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package zarf

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
)

func TestParseBothSchemas(t *testing.T) {
	for _, version := range []string{"", "zarf.dev/v1alpha1", "zarf.dev/v1beta1"} {
		t.Run(version, func(t *testing.T) {
			header := "metadata:\n  name: app\n  version: dev\n  architecture: arm64\n"
			if version != "" {
				header = "apiVersion: " + version + "\nkind: ZarfPackageConfig\n" + header
			}
			component := `components:
  - name: app
    only:
      flavor: upstream
      cluster:
        architecture: arm64
    images: [example.com/app:v1]
    imageArchives:
      - path: images.tar
        images: [example.com/archived:v1]
    import:
      path: ../common
`
			if version == "zarf.dev/v1beta1" {
				component = `components:
  - name: app
    selector:
      flavor: upstream
      architecture: arm64
    images:
      - name: example.com/app:v1
        id: app
        source: daemon
    imageArchives:
      - path: images.tar
        images:
          - name: example.com/archived:v1
            id: archived
    import:
      local: [{path: ../common.yaml}]
`
			}
			pkg, err := Parse([]byte(header + component))
			require.NoError(t, err)
			expectedVersion := version
			if expectedVersion == "" {
				expectedVersion = "zarf.dev/v1alpha1"
			}
			require.Equal(t, expectedVersion, pkg.APIVersion)
			require.Equal(t, Metadata{Name: "app", Version: "dev", Architecture: "arm64"}, pkg.Metadata)
			require.Len(t, pkg.Components, 1)
			c := pkg.Components[0]
			require.Equal(t, "upstream", c.Flavor)
			require.Equal(t, "arm64", c.Architecture)
			require.True(t, c.HasImports)
			source := "registry"
			if version == "zarf.dev/v1beta1" {
				source = "daemon"
			}
			require.Equal(t, []Image{{Name: "example.com/app:v1", Source: source}, {Name: "example.com/archived:v1", Source: "archive", Archive: "images.tar"}}, c.Images)
		})
	}
}

func TestRejectInvalidSources(t *testing.T) {
	for name, source := range map[string]string{
		"empty":                  "",
		"unknown version":        "apiVersion: zarf.dev/v2\nmetadata: {name: app}\n",
		"component config":       "kind: ZarfComponentConfig\nmetadata: {name: app}\n",
		"missing name":           "metadata: {version: dev}\n",
		"malformed metadata":     "metadata: [app]\n",
		"duplicate keys":         "metadata: {name: app, name: other}\n",
		"multiple docs":          "metadata: {name: app}\n---\nmetadata: {name: other}\n",
		"multiple with preamble": "# license\n%YAML 1.2\n---\nmetadata: {name: app}\n---\nmetadata: {name: other}\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(source))
			require.Error(t, err)
			_, _, err = UpdateVersion([]byte(source), "new")
			require.Error(t, err)
		})
	}
}

func TestPackageDocumentPreamble(t *testing.T) {
	for _, version := range []string{"zarf.dev/v1alpha1", "zarf.dev/v1beta1"} {
		for _, preamble := range []string{"# license\n---\n", "%YAML 1.2\n---\n", "# license\n%YAML 1.2\n---\n"} {
			t.Run(version+"/"+preamble, func(t *testing.T) {
				source := preamble + "apiVersion: " + version + "\nmetadata:\n  name: app\n  version: old\ncomponents: []\n...\n# trailing comment\n"
				pkg, err := Parse([]byte(source))
				require.NoError(t, err)
				require.Equal(t, "app", pkg.Metadata.Name)
				out, name, err := UpdateVersion([]byte(source), "new")
				require.NoError(t, err)
				require.Equal(t, "app", name)
				require.Equal(t, strings.Replace(source, "version: old", "version: new", 1), string(out))
				pkg, err = Parse(out)
				require.NoError(t, err)
				require.Equal(t, "new", pkg.Metadata.Version)
			})
		}
	}
}

func TestRegistryImages(t *testing.T) {
	pkg := Package{Components: []Component{
		{Name: "shared", Images: []Image{{Name: "common:v1", Source: "registry"}}},
		{Name: "first", Flavor: "upstream", Images: []Image{{Name: "first:v1", Source: "registry"}}},
		{Name: "second", Flavor: "upstream", Images: []Image{{Name: "second:v1", Source: "registry"}, {Name: "common:v1", Source: "registry"}}},
		{Name: "private", Flavor: "unicorn", Images: []Image{{Name: "private:v1", Source: "registry"}}},
	}}
	images, err := pkg.RegistryImages()
	require.NoError(t, err)
	require.Equal(t, map[string][]string{
		"upstream": {"common:v1", "first:v1", "second:v1"},
		"unicorn":  {"common:v1", "private:v1"},
	}, images)
	require.Equal(t, []string{"unicorn", "upstream"}, pkg.Flavors())
	pkg.Components = pkg.Components[:1]
	images, err = pkg.RegistryImages()
	require.NoError(t, err)
	require.Equal(t, map[string][]string{"": {"common:v1"}}, images)
}

func TestRegistryImagesRejectsIncompleteScans(t *testing.T) {
	for name, component := range map[string]Component{
		"import":             {Name: "app", HasImports: true},
		"daemon":             {Name: "app", Images: []Image{{Name: "app:v1", Source: "daemon"}}},
		"archive":            {Name: "app", Images: []Image{{Name: "app:v1", Source: "archive", Archive: "app.tar"}}},
		"unknown source":     {Name: "app", Images: []Image{{Name: "app:v1", Source: "unknown"}}},
		"missing image name": {Name: "app", Images: []Image{{Source: "registry"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := (Package{Components: []Component{component}}).RegistryImages()
			require.Error(t, err)
		})
	}
}

func TestRegistryImagesArchitecture(t *testing.T) {
	pkg := Package{Components: []Component{
		{Name: "amd", Architecture: "amd64", Images: []Image{{Name: "amd:v1", Source: "registry"}}},
		{Name: "arm", Architecture: "arm64", Images: []Image{{Name: "arm:v1", Source: "registry"}}},
	}}
	images, err := pkg.RegistryImages()
	require.NoError(t, err)
	require.Equal(t, []string{"amd:v1", "arm:v1"}, images[""])
	pkg.Metadata.Architecture = "arm64"
	images, err = pkg.RegistryImages()
	require.NoError(t, err)
	require.Equal(t, []string{"arm:v1"}, images[""])
}

func TestUpdateVersionPreservesSource(t *testing.T) {
	const source = `# package comment
apiVersion: zarf.dev/v1beta1
kind: ZarfPackageConfig
metadata:
  name: app # name comment
  version: dev # version comment
  annotations:
    custom: preserved
values:
  files: [values.yaml]
attachments:
  migration: MIGRATION.md
futureField: &shared
  enabled: true
otherField: *shared
components:
  - name: app
    selector: {flavor: upstream}
    import:
      local: [{path: common.yaml}]
    images:
      - name: example.com/app:v1
        id: app
        source: registry
    charts:
      - name: app
        version: 1.0.0
        local: {path: chart}
`
	for _, version := range []string{"1.2.3", "1.0", "true", "release: #special", "line\nbreak"} {
		t.Run(version, func(t *testing.T) {
			out, name, err := UpdateVersion([]byte(source), version)
			require.NoError(t, err)
			require.Equal(t, "app", name)
			var before, after map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(source), &before))
			require.NoError(t, yaml.Unmarshal(out, &after))
			before["metadata"].(map[string]any)["version"] = version
			require.Equal(t, before, after)
			for _, comment := range []string{"# package comment", "# name comment", "# version comment"} {
				require.Contains(t, string(out), comment)
			}
			require.Contains(t, string(out), "&shared")
			require.Contains(t, string(out), "*shared")
		})
	}
}

func TestUpdateVersionInsertsMissingVersion(t *testing.T) {
	for _, source := range []string{
		"metadata:\n  name: app # keep\ncomponents: []\n",
		"apiVersion: zarf.dev/v1beta1\nmetadata: {name: app}\ncomponents: []\n",
	} {
		out, _, err := UpdateVersion([]byte(source), "1.0")
		require.NoError(t, err)
		metadata, err := ReadMetadata(out)
		require.NoError(t, err)
		require.Equal(t, "1.0", metadata.Version)
		if strings.Contains(source, "# keep") {
			require.Contains(t, string(out), "# keep")
		}
	}
}

func TestUpdateVersionRejectsAnchoredMetadata(t *testing.T) {
	for _, source := range []string{
		"metadata: &meta {name: app, version: old}\nother: *meta\n",
		"metadata:\n  name: app\n  version: &v old\nother: *v\n",
	} {
		_, _, err := UpdateVersion([]byte(source), "new")
		require.Error(t, err)
	}
}
