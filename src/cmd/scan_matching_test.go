// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"github.com/stretchr/testify/require"
	"log/slog"
	"testing"
)

func TestMatchingScanRejectsAmbiguousPlatforms(t *testing.T) {
	results := map[string]string{
		"amd64": "/scans/app_v1--linux-amd64.json",
		"arm64": "/scans/app_v1--linux-arm64.json",
	}
	_, _, err := findMatchingScan("app", results, slog.Default())
	require.ErrorContains(t, err, "multiple released SBOM scans")
	delete(results, "arm64")
	file, found, err := findMatchingScan("app", results, slog.Default())
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, results["amd64"], file)
}
