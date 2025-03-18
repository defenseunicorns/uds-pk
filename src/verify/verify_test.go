// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/stretchr/testify/require"
)

func TestCheckForManifests(t *testing.T) {
	type wantResult struct {
		errorCount   int
		warnCount    int
		successCount int
	}
	tests := []struct {
		yaml string
		want wantResult
	}{
		{
			yaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			want: wantResult{errorCount: 0, warnCount: 0, successCount: 1},
		},
		{
			yaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    manifests:
      - name: simple-httpd-deployment
        namespace: httpd
        files:
          - httpd-deployment.yaml    	
    charts:
      - name: uds-app-config
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			want: wantResult{errorCount: 0, warnCount: 1, successCount: 0},
		},
	}

	for _, tt := range tests {
		tmpDir := t.TempDir()
		zarfYamlPath := filepath.Join(tmpDir, "zarf.yaml")

		if err := os.WriteFile(zarfYamlPath, []byte(tt.yaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}

		got := checkForManifests(zarfYamlPath)

		require.Equal(t, tt.want.errorCount, len(got.Errors))
		require.Equal(t, tt.want.warnCount, len(got.Warnings))
		require.Equal(t, tt.want.successCount, len(got.Successes))
	}
}

func TestGetNamespaces(t *testing.T) {
	tests := []struct {
		commonZarfYaml string
		rootZarfYaml   string
		want           []string
	}{
		{
			commonZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace1
      - name: app
        namespace: mynamespace2
`,
			rootZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace2
      - name: app
        namespace: mynamespace3
      - name: app
        namespace: mynamespace4
`,
			want: []string{"mynamespace1", "mynamespace2", "mynamespace3", "mynamespace4"},
		},
		{
			commonZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace1
      - name: app
        namespace: mynamespace2
`,
			rootZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
`,
			want: []string{"mynamespace1", "mynamespace2"},
		},
		{
			commonZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"
`,
			rootZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace2
      - name: app
        namespace: mynamespace3
      - name: app
        namespace: mynamespace4
`,
			want: []string{"mynamespace2", "mynamespace3", "mynamespace4"},
		},
	}

	for _, tt := range tests {
		tmpDir := t.TempDir()
		commonZarfYamlPath := filepath.Join(tmpDir, "common-zarf.yaml")
		rootZarfYamlPath := filepath.Join(tmpDir, "zarf.yaml")

		if err := os.WriteFile(commonZarfYamlPath, []byte(tt.commonZarfYaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}
		if err := os.WriteFile(rootZarfYamlPath, []byte(tt.rootZarfYaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}

		got, err := utils.GetNamespaces(commonZarfYamlPath, rootZarfYamlPath)

		require.Equal(t, err, nil)
		require.Equal(t, got, tt.want)
	}
}

func TestCheckForFlavors(t *testing.T) {
	type wantResult struct {
		errorCount   int
		warnCount    int
		successCount int
	}
	tests := []struct {
		yaml string
		want wantResult
	}{
		{
			yaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    only:
      flavor: registry1	
    charts:
      - name: uds-app-config
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			want: wantResult{errorCount: 0, warnCount: 0, successCount: 1},
		},
		{
			yaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			want: wantResult{errorCount: 1, warnCount: 0, successCount: 0},
		},
	}

	for _, tt := range tests {
		tmpDir := t.TempDir()
		zarfYamlPath := filepath.Join(tmpDir, "zarf.yaml")

		if err := os.WriteFile(zarfYamlPath, []byte(tt.yaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}

		got := checkForFlavors(zarfYamlPath)

		require.Equal(t, tt.want.errorCount, len(got.Errors))
		require.Equal(t, tt.want.warnCount, len(got.Warnings))
		require.Equal(t, tt.want.successCount, len(got.Successes))
	}
}

// verify proper codeowners
func TestCheckCodeOwners(t *testing.T) {
	type wantResult struct {
		expectedSuccesses []string
		expectedErrors    []string
	}

	tests := []struct {
		name       string
		codeOwners string
		want       wantResult
	}{
		{
			name: "Valid CODEOWNERS file with exact matches",
			codeOwners: `
/CODEOWNERS @jeff-mccoy @daveworth
/LICENS* @jeff-mccoy @austenbryan
`,
			want: wantResult{
				expectedSuccesses: []string{
					"Found: /CODEOWNERS @jeff-mccoy @daveworth",
					"Found: /LICENS* @jeff-mccoy @austenbryan",
				},
				expectedErrors: []string{}, // No errors expected
			},
		},
		{
			name: "Missing /LICENS* line",
			codeOwners: `
/CODEOWNERS @jeff-mccoy @daveworth
`,
			want: wantResult{
				expectedSuccesses: []string{
					"Found: /CODEOWNERS @jeff-mccoy @daveworth",
				},
				expectedErrors: []string{
					"Not found in CODEOWERS: /LICENS* @jeff-mccoy @austenbryan",
				},
			},
		},
	}

	for _, tt := range tests {
		{
			tmpDir := t.TempDir()
			codeOwnersPath := filepath.Join(tmpDir, "CODEOWNERS")

			content := strings.TrimSpace(tt.codeOwners)

			// Write test CODEOWNERS file
			if err := os.WriteFile(codeOwnersPath, []byte(content), 0644); err != nil {
				t.Fatalf("failed to write test CODEOWNERS file: %v", err)
			}

			// Define exact expected lines
			expectedLines := []string{
				"/CODEOWNERS @jeff-mccoy @daveworth",
				"/LICENS* @jeff-mccoy @austenbryan",
			}

			// Execute checkCodeOwners
			got := checkCodeOwners(codeOwnersPath, expectedLines)

			// Validate expected success messages
			require.Equal(t, len(tt.want.expectedSuccesses), len(got.Successes), "Mismatch in success count")
			for _, expectedSuccess := range tt.want.expectedSuccesses {
				require.Contains(t, got.Successes, expectedSuccess, "Expected success message missing")
			}

			// Validate expected error messages
			require.Equal(t, len(tt.want.expectedErrors), len(got.Errors), "Mismatch in error count")
			for _, expectedError := range tt.want.expectedErrors {
				require.Contains(t, got.Errors, expectedError, "Expected error message missing")
			}
		}
	}
}

// verify "tests" dir exists
// verify "tasks/test.yaml" exists
func TestCheckForTests(t *testing.T) {
	type wantResult struct {
		errorCount   int
		warnCount    int
		successCount int
	}

	// The table-driven test structure, modeled after your ideal test.
	tests := []struct {
		name       string // Test case name for clarity
		dir        string // The directory to check (e.g., "tasks")
		yaml       string // The YAML file name inside that directory (e.g., "test.yaml")
		createDir  bool   // Whether to create the directory
		createYaml bool   // Whether to create the YAML file
		want       wantResult
	}{
		{
			name:       "Both directory and YAML file exist",
			dir:        "tasks",
			yaml:       "test.yaml",
			createDir:  true,
			createYaml: true,
			// Expect two successes: one for the directory and one for the YAML file.
			want: wantResult{errorCount: 0, warnCount: 0, successCount: 2},
		},
		{
			name:       "Directory exists but YAML file missing",
			dir:        "tasks",
			yaml:       "test.yaml",
			createDir:  true,
			createYaml: false,
			// Expect one success (for the directory) and one error (for the missing YAML file).
			want: wantResult{errorCount: 1, warnCount: 0, successCount: 1},
		},
		{
			name:       "Directory missing (YAML file not even checked)",
			dir:        "tasks",
			yaml:       "test.yaml",
			createDir:  false,
			createYaml: false,
			// Expect one error (directory missing); YAML file check is skipped.
			want: wantResult{errorCount: 1, warnCount: 0, successCount: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary base directory for testing.
			tmpDir := t.TempDir()

			// Build the full path for the directory.
			dirPath := filepath.Join(tmpDir, tt.dir)
			// Build the full path for the YAML file if one is specified.
			yamlPath := ""
			if tt.yaml != "" {
				yamlPath = filepath.Join(dirPath, tt.yaml)
			}

			// Create the directory if needed.
			if tt.createDir {
				err := os.MkdirAll(dirPath, 0755)
				require.NoError(t, err, "failed to create directory")
			}

			// Create the YAML file if needed.
			if tt.createYaml {
				err := os.WriteFile(yamlPath, []byte("test: value"), 0644)
				require.NoError(t, err, "failed to create YAML file")
			}

			// Call the function under test.
			got := checkForTests(dirPath, yamlPath)

			// Verify that the results match our expectations.
			require.Equal(t, tt.want.errorCount, len(got.Errors), "Mismatch in error count")
			require.Equal(t, tt.want.warnCount, len(got.Warnings), "Mismatch in warn count")
			require.Equal(t, tt.want.successCount, len(got.Successes), "Mismatch in success count")
		})
	}
}

// func TestKeycloakClient(t *testing.T) {
// 	tests := []struct {
// 		name             string
// 		valuesContent    string // Contents for values.yaml
// 		otherContent     string // Contents for other.yaml
// 		key              string // Key to check in values.yaml
// 		dependentKey     string // Dependent key to check in other.yaml
// 		expectSuccess    bool   // Should we expect a success (dependent key found) when key is enabled?
// 		expectErrorCount int    // Expected number of errors
// 		expectWarnCount  int    // Expected number of warnings
// 	}{
// 		{
// 			name: "SSO enabled",
// 			valuesContent: `
// sso:
//   enabled: true
// `,
// 			otherContent: `
// dependentFeature: enabled
// `,
// 			key:              "featureX",
// 			dependentKey:     "dependentFeature",
// 			expectSuccess:    true,
// 			expectErrorCount: 0,
// 			expectWarnCount:  0,
// 		},
// 		{
// 			name: "Key enabled but dependent key missing",
// 			valuesContent: `
// featureX: true
// `,
// 			otherContent: `
// otherKey: value
// `,
// 			key:              "featureX",
// 			dependentKey:     "dependentFeature",
// 			expectSuccess:    false,
// 			expectErrorCount: 1,
// 			expectWarnCount:  0,
// 		},
// 		{
// 			name: "Key not enabled (false)",
// 			valuesContent: `
// featureX: false
// `,
// 			otherContent: `
// dependentFeature: enabled
// `,
// 			key:              "featureX",
// 			dependentKey:     "dependentFeature",
// 			expectSuccess:    false,
// 			expectErrorCount: 0,
// 			expectWarnCount:  1,
// 		},
// 		{
// 			name: "Key missing entirely",
// 			valuesContent: `
// otherKey: value
// `,
// 			otherContent: `
// dependentFeature: enabled
// `,
// 			key:              "featureX",
// 			dependentKey:     "dependentFeature",
// 			expectSuccess:    false,
// 			expectErrorCount: 0,
// 			expectWarnCount:  1,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			// Create a temporary directory
// 			tmpDir := t.TempDir()

// 			// Define file paths for values.yaml and other.yaml
// 			valuesPath := filepath.Join(tmpDir, "values.yaml")
// 			otherPath := filepath.Join(tmpDir, "other.yaml")

// 			// Write the YAML contents to the respective files
// 			err := os.WriteFile(valuesPath, []byte(tt.valuesContent), 0644)
// 			require.NoError(t, err, "Failed to write values.yaml")

// 			err = os.WriteFile(otherPath, []byte(tt.otherContent), 0644)
// 			require.NoError(t, err, "Failed to write other.yaml")

// 			// Call the function under test
// 			results := checkValuesAndOtherFile(valuesPath, otherPath, tt.key, tt.dependentKey)

// 			// Verify outcomes based on the expectations.
// 			if tt.expectSuccess {
// 				require.Equal(t, 0, len(results.Errors), "Expected no errors")
// 				require.Greater(t, len(results.Successes), 0, "Expected at least one success")
// 			} else {
// 				require.Equal(t, tt.expectErrorCount, len(results.Errors), "Mismatch in error count")
// 			}
// 			require.Equal(t, tt.expectWarnCount, len(results.Warnings), "Mismatch in warn count")
// 		})
// 	}
// }
