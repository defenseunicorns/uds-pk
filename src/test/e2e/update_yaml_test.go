// Copyright 2024-2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	uds "github.com/defenseunicorns/uds-cli/pkg/legacy/types"
	releaseTypes "github.com/defenseunicorns/uds-pk/src/types"
	packageinfo "github.com/defenseunicorns/uds-pk/src/zarf"
	goyaml "github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
	zarf "github.com/zarf-dev/zarf/src/api/v1alpha1"
)

func TestUpdateYamlCommandMergedMetadata(t *testing.T) {
	for _, apiVersion := range []string{"zarf.dev/v1alpha1", "zarf.dev/v1beta1"} {
		t.Run(apiVersion, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(dir, "bundle"), 0o755))
			e2e.CreateUDSBundleYaml(t, filepath.Join(dir, "bundle"))
			e2e.CreateFlavorReleaseConfig(t, dir, releaseTypes.Flavor{Name: "upstream", Version: "2.1.0"})
			source := "apiVersion: " + apiVersion + `
kind: ZarfPackageConfig
defaults: &defaults
  name: testing-package
  version: old
  annotations: {note: preserved}
metadata:
  <<: *defaults
other: *defaults
components: []
`
			packagePath := filepath.Join(dir, "zarf.yaml")
			require.NoError(t, os.WriteFile(packagePath, []byte(source), 0o644))
			stdout, stderr, err := e2e.UDSPKDir(dir, "release", "update-yaml", "upstream")
			require.NoError(t, err, stdout, stderr)
			data, err := os.ReadFile(packagePath)
			require.NoError(t, err)
			var values map[string]any
			require.NoError(t, goyaml.Unmarshal(data, &values))
			require.Equal(t, "2.1.0", values["metadata"].(map[string]any)["version"])
			require.Equal(t, "old", values["defaults"].(map[string]any)["version"])
			require.Equal(t, "old", values["other"].(map[string]any)["version"])
			pkg, err := packageinfo.ReadFile(packagePath)
			require.NoError(t, err)
			require.Equal(t, "2.1.0", pkg.Metadata.Version)
		})
	}
}

func TestUpdateYamlCommandBetaPackage(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "bundle"), 0o755))
	e2e.CreateUDSBundleYaml(t, filepath.Join(dir, "bundle"))
	e2e.CreateFlavorReleaseConfig(t, dir, releaseTypes.Flavor{Name: "upstream", Version: "2.0.0-uds.0"})
	const source = `# beta source
apiVersion: zarf.dev/v1beta1
kind: ZarfPackageConfig
metadata:
  name: testing-package
  version: dev # keep version note
attachments:
  migration: MIGRATION.md
components:
  - name: app
    selector: {flavor: upstream}
    images:
      - name: example.com/app:v1
        id: app
`
	packagePath := filepath.Join(dir, "zarf.yaml")
	require.NoError(t, os.WriteFile(packagePath, []byte(source), 0o640))
	stdout, stderr, err := e2e.UDSPKDir(dir, "release", "update-yaml", "upstream")
	require.NoError(t, err, stdout, stderr)
	data, err := os.ReadFile(packagePath)
	require.NoError(t, err)
	require.Equal(t, strings.Replace(source, "version: dev", "version: 2.0.0-uds.0", 1), string(data))
	info, err := os.Stat(packagePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
	pkg, err := packageinfo.ReadFile(packagePath)
	require.NoError(t, err)
	require.Equal(t, "2.0.0-uds.0", pkg.Metadata.Version)
	require.Len(t, pkg.Components[0].Images, 1)
	var bundle uds.UDSBundle
	require.NoError(t, e2e.LoadYaml(filepath.Join(dir, "bundle", "uds-bundle.yaml"), &bundle))
	require.Equal(t, "2.0.0-uds.0-upstream", bundle.Packages[0].Ref)
}

func TestUpdateYamlCommand(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle")
	defer e2e.CleanupSandboxDir(t)

	e2e.CreateZarfYaml(t, "src/test/sandbox")
	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle")
	e2e.CreateFlavorReleaseConfig(t, "src/test/sandbox",
		releaseTypes.Flavor{Name: "base", Version: "1.0.0-uds.0"},
		releaseTypes.Flavor{Version: "1.0.0-flavorless.0"},
	)

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "update-yaml", "base", "-d", "sandbox")
	require.NoError(t, err, stdout, stderr)

	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml("src/test/sandbox/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-uds.0", zarfPackage.Metadata.Version)

	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-uds.0-base", bundle.Metadata.Version)
	require.Equal(t, "1.0.0-uds.0-base", bundle.Packages[0].Ref)
}

func TestUpdateYamlCommandBetaPackage(t *testing.T) {
	const source = `apiVersion: zarf.dev/v1beta1
kind: ZarfPackageConfig
metadata:
  name: testing-package
  version: dev
  annotations:
    example.com/owner: platform
values:
  files: [values.yaml]
  schema: values.schema.json
attachments:
  migration: MIGRATION.md
components:
  - name: app
    selector:
      flavor: upstream
    import:
      local:
        - path: components/upstream.yaml
    images:
      - name: example.com/app:1.0.0
        id: app
        source: registry
    charts:
      - name: app
        local:
          path: chart
        valuesFiles:
          - path: values/config.yaml.tmpl
            enableTemplating: true
        values:
          - sourcePath: .app
            targetPath: .
`
	for _, scenario := range []string{"success", "invalid bundle", "missing chart"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "bundle"), 0o755))
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "chart"), 0o755))
			packagePath := filepath.Join(dir, "zarf.yaml")
			bundlePath := filepath.Join(dir, "bundle", "uds-bundle.yaml")
			chartPath := filepath.Join(dir, "chart", "Chart.yaml")
			require.NoError(t, os.WriteFile(packagePath, []byte(source), 0o640))
			require.NoError(t, os.WriteFile(chartPath, []byte("name: app\nversion: dev\n"), 0o640))
			e2e.CreateUDSBundleYaml(t, filepath.Join(dir, "bundle"))
			config := releaseTypes.ReleaseConfig{
				Flavors: []releaseTypes.Flavor{{Name: "upstream", Version: "2.0.0-uds.0"}},
				Charts:  []releaseTypes.Chart{{Path: "chart", VersionFromFlavor: true}},
			}
			if scenario == "invalid bundle" {
				require.NoError(t, os.WriteFile(bundlePath, []byte("not: [valid"), 0o644))
			}
			if scenario == "missing chart" {
				config.Charts[0].Path = "missing-chart"
			}
			e2e.WriteReleaseConfig(t, dir, config)
			originals := map[string][]byte{}
			for _, path := range []string{packagePath, bundlePath, chartPath} {
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				originals[path] = data
			}

			stdout, stderr, err := e2e.UDSPKDir(dir, "release", "update-yaml", "upstream")
			if scenario != "success" {
				require.Error(t, err, stdout, stderr)
				for path, original := range originals {
					data, err := os.ReadFile(path)
					require.NoError(t, err)
					require.Equal(t, original, data, path)
				}
				return
			}
			require.NoError(t, err, stdout, stderr)

			// Compare source fields without decoding through the schema under test.
			var expected, actual map[string]any
			require.NoError(t, goyaml.Unmarshal([]byte(source), &expected))
			expected["metadata"].(map[string]any)["version"] = "2.0.0-uds.0"
			require.NoError(t, e2e.LoadYaml(packagePath, &actual))
			for key, value := range expected {
				require.Equal(t, value, actual[key], key)
			}
			info, err := os.Stat(packagePath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
			var bundle uds.UDSBundle
			require.NoError(t, e2e.LoadYaml(bundlePath, &bundle))
			require.Equal(t, "2.0.0-uds.0-upstream", bundle.Metadata.Version)
			require.Equal(t, "2.0.0-uds.0-upstream", bundle.Packages[0].Ref)
			var chart map[string]any
			require.NoError(t, e2e.LoadYaml(chartPath, &chart))
			require.Equal(t, "2.0.0-uds.0", chart["version"])
		})
	}
}

func TestUpdateYamlCommandWithNextBundleOnly(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle")
	defer e2e.CleanupSandboxDir(t)

	e2e.CreateZarfYaml(t, "src/test/sandbox")
	e2e.CreateFlavorReleaseConfig(t, "src/test/sandbox",
		releaseTypes.Flavor{Name: "upstream", Version: "1.2.3-uds.0"},
	)

	const originalBundle = `locals {
  notes = file("notes.txt")
}

uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name = "testing-bundle"
  version = "dev"
  description = local.notes
}

package "application" {
  source = "../zarf-package-testing-package-${sys.arch}-dev.tar.zst"
  signature_verification { verify = false }
}

package "testing-package-resources" {
  source = "../zarf-package-testing-package-resources-${sys.arch}-dev.tar.zst"
  depends_on = [package.application]
  signature_verification { verify = false }
}
`
	bundlePath := "src/test/sandbox/bundle/bundle.uds.hcl"
	legacyBundlePath := "src/test/sandbox/bundle/uds-bundle.yaml"
	require.NoError(t, os.WriteFile("src/test/sandbox/bundle/notes.txt", []byte("Release notes"), 0o644))
	require.NoError(t, os.WriteFile(bundlePath, []byte(originalBundle), 0o644))
	require.NoFileExists(t, legacyBundlePath)

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "update-yaml", "upstream", "-d", "sandbox")
	require.NoError(t, err, stdout, stderr)

	var zarfPackage zarf.ZarfPackage
	require.NoError(t, e2e.LoadYaml("src/test/sandbox/zarf.yaml", &zarfPackage))
	require.Equal(t, "1.2.3-uds.0", zarfPackage.Metadata.Version)

	bundle, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	want := strings.Replace(originalBundle, `version = "dev"`, `version = "1.2.3-uds.0-upstream"`, 1)
	want = strings.Replace(want,
		"zarf-package-testing-package-${sys.arch}-dev.tar.zst",
		"zarf-package-testing-package-${sys.arch}-1.2.3-uds.0-upstream.tar.zst", 1)
	require.Equal(t, want, string(bundle))
	require.NoFileExists(t, legacyBundlePath)
}

func TestUpdateYamlCommandPackageOnlyRepoWithoutBundle(t *testing.T) {
	e2e.CreateSandboxDir(t)
	defer e2e.CleanupSandboxDir(t)

	packageDir := filepath.Join("src/test/sandbox", "packages", "example")
	require.NoError(t, os.MkdirAll(packageDir, 0o755))
	e2e.CreateAltZarfYaml(t, "example", packageDir)
	e2e.CreatePackageReleaseConfig(t, "src/test/sandbox", releaseTypes.Package{
		Name: "example",
		Path: "packages/example",
		Flavors: []releaseTypes.Flavor{
			{Name: "upstream", Version: "1.0.0"},
		},
	})

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "update-yaml", "upstream", "-d", "sandbox", "-p", "example")
	require.NoError(t, err, stdout, stderr)

	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml(filepath.Join(packageDir, "zarf.yaml"), &zarfPackage)
	require.NoError(t, err)
	require.Equal(t, "1.0.0", zarfPackage.Metadata.Version)
}

func TestUpdateYamlCommandPackageInMixedRepoWithoutBundle(t *testing.T) {
	e2e.CreateSandboxDir(t, "packages")
	defer e2e.CleanupSandboxDir(t)

	packageDir := filepath.Join("src/test/sandbox", "packages", "example")
	require.NoError(t, os.MkdirAll(packageDir, 0o755))
	e2e.CreateAltZarfYaml(t, "example", packageDir)
	e2e.WriteReleaseConfig(t, "src/test/sandbox", releaseTypes.ReleaseConfig{
		Flavors: []releaseTypes.Flavor{
			{Name: "base", Version: "9.9.9"},
		},
		Packages: []releaseTypes.Package{
			{
				Name: "example",
				Path: "packages/example",
				Flavors: []releaseTypes.Flavor{
					{Name: "upstream", Version: "1.0.0"},
				},
			},
		},
	})

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "update-yaml", "upstream", "-d", "sandbox", "-p", "example")
	require.NoError(t, err, stdout, stderr)

	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml(filepath.Join(packageDir, "zarf.yaml"), &zarfPackage)
	require.NoError(t, err)
	require.Equal(t, "1.0.0", zarfPackage.Metadata.Version)
}
