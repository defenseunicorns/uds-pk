// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
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
