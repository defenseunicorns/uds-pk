// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateSemver(t *testing.T) {
	tests := []struct {
		name    string
		version string
		valid   bool
	}{
		{"valid basic semver", "1.0.0", true},
		{"valid uds version", "1.0.0-uds.0", true},
		{"valid prerelease", "1.0.0-alpha.1", true},
		{"valid build metadata", "1.0.0+build.1", true},
		{"invalid v prefix", "v1.0.0", false},
		{"invalid underscore", "1.0.0_uds.0", false},
		{"invalid too many parts", "1.0.0.0", false},
		{"invalid leading zeros", "01.0.0", false},
		{"empty version", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSemver(tt.version)
			if tt.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestLoadReleaseConfigWithValidation(t *testing.T) {
	tests := []struct {
		name             string
		yamlContent      string
		enableValidation bool
		expectError      bool
	}{
		{
			name: "valid versions with validation enabled",
			yamlContent: `flavors:
  - name: test
    version: "1.0.0-uds.0"`,
			enableValidation: true,
			expectError:      false,
		},
		{
			name: "valid versions with validation disabled",
			yamlContent: `flavors:
  - name: test
    version: "1.0.0-uds.0"`,
			enableValidation: false,
			expectError:      false,
		},
		{
			name: "invalid versions with validation enabled",
			yamlContent: `flavors:
  - name: test
    version: "v1.0.0"`,
			enableValidation: true,
			expectError:      true,
		},
		{
			name: "invalid versions with validation disabled",
			yamlContent: `flavors:
  - name: test
    version: "v1.0.0"`,
			enableValidation: false,
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory and file
			tempDir, err := os.MkdirTemp("", "uds-pk-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tempDir)

			yamlPath := filepath.Join(tempDir, "releaser.yaml")
			err = os.WriteFile(yamlPath, []byte(tt.yamlContent), 0644)
			require.NoError(t, err)

			// Test the function
			_, err = LoadReleaseConfigWithValidation(tempDir, tt.enableValidation)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoadReleaseConfig_BackwardCompatibility(t *testing.T) {
	// Test that LoadReleaseConfig still defaults to validation enabled
	tempDir, err := os.MkdirTemp("", "uds-pk-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Valid content should work
	validYaml := `flavors:
  - name: test
    version: "1.0.0-uds.0"`
	yamlPath := filepath.Join(tempDir, "releaser.yaml")
	err = os.WriteFile(yamlPath, []byte(validYaml), 0644)
	require.NoError(t, err)

	_, err = LoadReleaseConfig(tempDir)
	require.NoError(t, err)

	// Invalid content should fail
	invalidYaml := `flavors:
  - name: test
    version: "v1.0.0"`
	err = os.WriteFile(yamlPath, []byte(invalidYaml), 0644)
	require.NoError(t, err)

	_, err = LoadReleaseConfig(tempDir)
	require.Error(t, err)
}
