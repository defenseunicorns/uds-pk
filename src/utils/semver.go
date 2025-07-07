// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

// ValidateSemver validates that a version string is compliant with Semantic Versioning 2.0.0 specification
func ValidateSemver(version string) error {
	_, err := semver.StrictNewVersion(version)
	if err != nil {
		return fmt.Errorf("invalid semver '%s': %w", version, err)
	}
	return nil
}
