// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	uds "github.com/defenseunicorns/uds-cli/src/types"
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/stretchr/testify/require"
	zarf "github.com/zarf-dev/zarf/src/api/v1alpha1"
)

func TestPrepareZarfYamlUpdate(t *testing.T) {
	tests := []struct {
		name          string
		flavor        types.Flavor
		initialYaml   string
		expectedName  string
		expectedError bool
	}{
		{
			name: "basic update",
			flavor: types.Flavor{
				Name:    "test",
				Version: "1.2.3",
			},
			initialYaml: `
metadata:
  name: test-package
  version: 1.0.0
`,
			expectedName:  "test-package",
			expectedError: false,
		},
		{
			name: "file doesn't exist",
			flavor: types.Flavor{
				Name:    "test",
				Version: "1.2.3",
			},
			initialYaml:   "non-existent",
			expectedName:  "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp dir for test
			tmpDir := t.TempDir()
			zarfPath := filepath.Join(tmpDir, "zarf.yaml")

			// Write initial YAML if it's not testing for non-existent file
			if tt.initialYaml != "non-existent" {
				err := os.WriteFile(zarfPath, []byte(tt.initialYaml), 0644)
				require.NoError(t, err)
			}

			update, packageName, err := prepareZarfYamlUpdate(tt.flavor, tmpDir, "")

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, zarfPath, update.path)
				require.Equal(t, tt.expectedName, packageName)
				require.NoError(t, os.WriteFile(update.path, update.content, update.mode))

				var zarfPackage zarf.ZarfPackage
				err = utils.LoadYaml(zarfPath, &zarfPackage)
				require.NoError(t, err)
				require.Equal(t, tt.flavor.Version, zarfPackage.Metadata.Version)
			}
		})
	}
}

func TestPrepareChartUpdates(t *testing.T) {
	flavor := types.Flavor{Name: "base", Version: "1.2.3-uds.0"}

	tests := []struct {
		name         string
		chartContent string
		chartConfig  types.Chart
		assertions   func(t *testing.T, content string)
	}{
		{
			name:         "flavor-derived version",
			chartContent: "apiVersion: v2\nname: flavor-chart\nversion: dev\ndescription: preserved\n",
			chartConfig:  types.Chart{Path: "chart", VersionFromFlavor: true},
			assertions: func(t *testing.T, content string) {
				require.Contains(t, content, "version: 1.2.3-uds.0")
				require.Contains(t, content, "description: preserved")
				require.NotContains(t, content, "appVersion:")
			},
		},
		{
			name:         "explicit version preserves existing fields",
			chartContent: "apiVersion: v2\nname: explicit-chart\nversion: dev\nappVersion: old\nmaintainers:\n  - name: Alice\n",
			chartConfig:  types.Chart{Path: "chart", Version: "2.4.0"},
			assertions: func(t *testing.T, content string) {
				require.Contains(t, content, "version: 2.4.0")
				require.Contains(t, content, "appVersion: old")
				require.Contains(t, content, "maintainers:")
			},
		},
		{
			name:         "adds appVersion when missing",
			chartContent: "apiVersion: v2\nname: without-app-version\nversion: dev\n",
			chartConfig:  types.Chart{Path: "chart", VersionFromFlavor: true, UpdateAppVersion: true},
			assertions: func(t *testing.T, content string) {
				require.True(t, strings.HasSuffix(content, "appVersion: 1.2.3-uds.0\n"))
			},
		},
		{
			name:         "non-semver version",
			chartContent: "apiVersion: v2\nname: non-semver\nversion: dev\n",
			chartConfig:  types.Chart{Path: "chart", Version: "not-a-semver-version"},
			assertions: func(t *testing.T, content string) {
				require.Contains(t, content, "version: not-a-semver-version")
			},
		},
		{
			name:         "adds version field when missing",
			chartContent: "apiVersion: v2\nname: without-version\ndescription: preserved\n",
			chartConfig:  types.Chart{Path: "chart", Version: "3.2.1"},
			assertions: func(t *testing.T, content string) {
				require.Contains(t, content, "version: 3.2.1")
				require.Contains(t, content, "description: preserved")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			releaseDir := t.TempDir()
			chartDir := filepath.Join(releaseDir, tt.chartConfig.Path)
			require.NoError(t, os.MkdirAll(chartDir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(tt.chartContent), 0640))

			updates, err := prepareChartUpdates(flavor, releaseDir, []types.Chart{tt.chartConfig})
			require.NoError(t, err)
			require.Len(t, updates, 1)

			tt.assertions(t, string(updates[0].content))
		})
	}
}

func TestPrepareChartUpdatesErrors(t *testing.T) {
	_, err := prepareChartUpdates(types.Flavor{Version: "1.2.3"}, t.TempDir(), []types.Chart{{Path: "missing-chart", Version: "2.4.0"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing-chart")
}

func TestPrepareBundleUpdate(t *testing.T) {
	tests := []struct {
		name        string
		flavor      types.Flavor
		packageName string
		initialYaml string
		expectNil   bool
	}{
		{
			name: "update existing package",
			flavor: types.Flavor{
				Name:    "test",
				Version: "1.2.3",
			},
			packageName: "test-package",
			initialYaml: `
metadata:
  name: test-bundle
  version: 1.0.0
packages:
  - name: test-package
    ref: 1.0.0
  - name: other-package
    ref: 2.0.0
`,
			expectNil: false,
		},
		{
			name: "package not found",
			flavor: types.Flavor{
				Name:    "test",
				Version: "1.2.3",
			},
			packageName: "missing-package",
			initialYaml: `
metadata:
  name: test-bundle
  version: 1.0.0
packages:
  - name: test-package
    ref: 1.0.0
`,
			expectNil: false,
		},
		{
			name: "file doesn't exist",
			flavor: types.Flavor{
				Name:    "test",
				Version: "1.2.3",
			},
			packageName: "test-package",
			initialYaml: "non-existent",
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			bundleDir := filepath.Join(tmpDir, "bundle")
			err := os.MkdirAll(bundleDir, 0755)
			require.NoError(t, err)

			bundlePath := filepath.Join(bundleDir, "uds-bundle.yaml")

			if tt.initialYaml != "non-existent" {
				err = os.WriteFile(bundlePath, []byte(tt.initialYaml), 0644)
				require.NoError(t, err)
			}

			update, err := prepareBundleUpdate(tt.flavor, tmpDir, tt.packageName)
			require.NoError(t, err)
			if tt.expectNil {
				require.Nil(t, update)
				return
			}

			require.NotNil(t, update)
			require.Equal(t, bundlePath, update.path)
			require.NoError(t, os.WriteFile(update.path, update.content, update.mode))

			var bundle uds.UDSBundle
			err = utils.LoadYaml(bundlePath, &bundle)
			require.NoError(t, err)

			expectedVersion := tt.flavor.Version
			if tt.flavor.Name != "" {
				expectedVersion = tt.flavor.Version + "-" + tt.flavor.Name
			}
			require.Equal(t, expectedVersion, bundle.Metadata.Version)

			for _, pkg := range bundle.Packages {
				if pkg.Name == tt.packageName {
					require.Equal(t, expectedVersion, pkg.Ref)
				}
			}
		})
	}
}

func TestUpdateYamlsSkipsMissingBundle(t *testing.T) {
	releaseDir := t.TempDir()
	flavor := types.Flavor{Version: "1.2.3"}
	require.NoError(t, os.WriteFile(filepath.Join(releaseDir, "zarf.yaml"), []byte("metadata:\n  name: test-package\n  version: dev\n"), 0644))

	err := UpdateYamls(flavor, "", releaseDir, nil)
	require.NoError(t, err)

	var zarfPackage zarf.ZarfPackage
	require.NoError(t, utils.LoadYaml(filepath.Join(releaseDir, "zarf.yaml"), &zarfPackage))
	require.Equal(t, "1.2.3", zarfPackage.Metadata.Version)
}

func TestUpdateYamlsDoesNotModifyZarfWhenBundleIsInvalid(t *testing.T) {
	releaseDir := t.TempDir()
	flavor := types.Flavor{Version: "1.2.3"}
	zarfPath := filepath.Join(releaseDir, "zarf.yaml")
	bundleDir := filepath.Join(releaseDir, "bundle")
	require.NoError(t, os.MkdirAll(bundleDir, 0755))
	require.NoError(t, os.WriteFile(zarfPath, []byte("metadata:\n  name: test-package\n  version: dev\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(bundleDir, "uds-bundle.yaml"), []byte("not: [valid"), 0644))

	err := UpdateYamls(flavor, "", releaseDir, nil)
	require.Error(t, err)

	var zarfPackage zarf.ZarfPackage
	require.NoError(t, utils.LoadYaml(zarfPath, &zarfPackage))
	require.Equal(t, "dev", zarfPackage.Metadata.Version)
}

func TestUpdateYamlsDoesNotModifyZarfWhenChartPreparationFails(t *testing.T) {
	releaseDir := t.TempDir()
	flavor := types.Flavor{Version: "1.2.3"}
	zarfPath := filepath.Join(releaseDir, "zarf.yaml")
	require.NoError(t, os.WriteFile(zarfPath, []byte("metadata:\n  name: test-package\n  version: dev\n"), 0644))

	err := UpdateYamls(flavor, "", releaseDir, []types.Chart{{Path: "missing-chart", Version: "2.4.0"}})
	require.Error(t, err)

	var zarfPackage zarf.ZarfPackage
	require.NoError(t, utils.LoadYaml(zarfPath, &zarfPackage))
	require.Equal(t, "dev", zarfPackage.Metadata.Version)
}
