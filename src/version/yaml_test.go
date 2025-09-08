// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"os"
	"path/filepath"
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

func TestUpdateBundleYaml(t *testing.T) {
	// Save current working directory
	cwd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(cwd)

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
