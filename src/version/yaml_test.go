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

func TestUpdateZarfYaml(t *testing.T) {
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

			// Call the function
			packageName, err := updateZarfYaml(tt.flavor, tmpDir)

			// Check results
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedName, packageName)

				// Verify the file was updated correctly
				var zarfPackage zarf.ZarfPackage
				err = utils.LoadYaml(zarfPath, &zarfPackage)
				require.NoError(t, err)
				require.Equal(t, tt.flavor.Version, zarfPackage.Metadata.Version)
			}
		})
	}
}

func TestPrepareChartUpdates(t *testing.T) {
	releaseDir := t.TempDir()
	flavor := types.Flavor{Name: "base", Version: "1.2.3-uds.0"}
	charts := []struct {
		path    string
		content string
	}{
		{"flavor-chart", "apiVersion: v2\nname: flavor-chart\nversion: dev\ndescription: preserved\n"},
		{"explicit-chart", "apiVersion: v2\nname: explicit-chart\nversion: dev\nappVersion: old\nmaintainers:\n  - name: Alice\n"},
		{"without-app-version", "apiVersion: v2\nname: without-app-version\nversion: dev\n"},
		{"non-semver", "apiVersion: v2\nname: non-semver\nversion: dev\n"},
		{"without-version", "apiVersion: v2\nname: without-version\ndescription: preserved\n"},
	}
	for _, chart := range charts {
		chartDir := filepath.Join(releaseDir, chart.path)
		require.NoError(t, os.MkdirAll(chartDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(chart.content), 0640))
	}

	updates, err := prepareChartUpdates(flavor, releaseDir, []types.Chart{
		{Path: "flavor-chart", VersionFromFlavor: true},
		{Path: "explicit-chart", Version: "2.4.0"},
		{Path: "without-app-version", VersionFromFlavor: true, UpdateAppVersion: true},
		{Path: "non-semver", Version: "not-a-semver-version"},
		{Path: "without-version", Version: "3.2.1"},
	})
	require.NoError(t, err)
	require.Len(t, updates, 5)
	require.Equal(t, os.FileMode(0640), updates[0].mode.Perm())

	contents := make(map[string]string)
	for _, update := range updates {
		contents[filepath.Base(filepath.Dir(update.path))] = string(update.content)
	}
	require.Contains(t, contents["flavor-chart"], "version: 1.2.3-uds.0")
	require.Contains(t, contents["flavor-chart"], "description: preserved")
	require.NotContains(t, contents["flavor-chart"], "appVersion:")
	require.Contains(t, contents["explicit-chart"], "version: 2.4.0")
	require.Contains(t, contents["explicit-chart"], "appVersion: old")
	require.Contains(t, contents["explicit-chart"], "maintainers:")
	require.True(t, strings.HasSuffix(contents["without-app-version"], "appVersion: \"1.2.3-uds.0\"\n"))
	require.Contains(t, contents["non-semver"], "version: not-a-semver-version")
	require.Contains(t, contents["without-version"], "version: 3.2.1")
	require.Contains(t, contents["without-version"], "description: preserved")
}

func TestPrepareChartUpdatesErrors(t *testing.T) {
	_, err := prepareChartUpdates(types.Flavor{Version: "1.2.3"}, t.TempDir(), []types.Chart{{Path: "missing-chart", Version: "2.4.0"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing-chart")
}

func TestUpdateBundleYaml(t *testing.T) {
	// Save current working directory
	cwd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		err := os.Chdir(cwd)
		if err != nil {
			t.Logf("Failed to change back to original directory: %v", err)
		}
	}()

	tests := []struct {
		name          string
		flavor        types.Flavor
		packageName   string
		initialYaml   string
		expectedError bool
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
			expectedError: false,
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
			expectedError: false,
		},
		{
			name: "file doesn't exist",
			flavor: types.Flavor{
				Name:    "test",
				Version: "1.2.3",
			},
			packageName:   "test-package",
			initialYaml:   "non-existent",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp dir for test
			tmpDir := t.TempDir()
			bundleDir := filepath.Join(tmpDir, "bundle")
			err := os.MkdirAll(bundleDir, 0755)
			require.NoError(t, err)

			bundlePath := filepath.Join(bundleDir, "uds-bundle.yaml")

			// Write initial YAML if it's not testing for non-existent file
			if tt.initialYaml != "non-existent" {
				err = os.WriteFile(bundlePath, []byte(tt.initialYaml), 0644)
				require.NoError(t, err)
			}

			// Change to temp dir for test
			err = os.Chdir(tmpDir)
			require.NoError(t, err)

			// Call the function
			err = updateBundleYaml(tt.flavor, tt.packageName)

			// Check results
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify the file was updated correctly
				var bundle uds.UDSBundle
				err = utils.LoadYaml("bundle/uds-bundle.yaml", &bundle)
				require.NoError(t, err)

				// Check bundle version was updated
				expectedVersion := tt.flavor.Version
				if tt.flavor.Name != "" {
					expectedVersion = tt.flavor.Version + "-" + tt.flavor.Name
				}
				require.Equal(t, expectedVersion, bundle.Metadata.Version)

				// Check if package ref was updated
				for _, pkg := range bundle.Packages {
					if pkg.Name == tt.packageName {
						require.Equal(t, expectedVersion, pkg.Ref)
					}
				}
			}
		})
	}
}
