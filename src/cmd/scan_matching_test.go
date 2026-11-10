// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/scan"
	"github.com/stretchr/testify/require"
)

func writeScanIdentity(t *testing.T, file string, identity scan.Identity) string {
	t.Helper()
	value, err := json.Marshal(identity)
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{"metadata": map[string]any{"properties": []map[string]string{{"name": "uds-pk:scan-identity", "value": string(value)}}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, data, 0o600))
	return file
}

func testIdentity(t *testing.T, image, platform, imageID string) scan.Identity {
	t.Helper()
	identity, err := scan.ImageIdentity(image)
	require.NoError(t, err)
	identity.Platform = platform
	identity.ImageID = imageID
	return identity
}

func TestMatchingScanRejectsAmbiguousPlatforms(t *testing.T) {
	dir := t.TempDir()
	image := testIdentity(t, "example.com/app:v2", "", "")
	results := map[string]string{
		"amd64": writeScanIdentity(t, filepath.Join(dir, "app_v1--linux-amd64.json"), testIdentity(t, "example.com/app:v1", "linux/amd64", "sha256:amd")),
		"arm64": writeScanIdentity(t, filepath.Join(dir, "app_v1--linux-arm64.json"), testIdentity(t, "example.com/app:v1", "linux/arm64", "sha256:arm")),
	}
	_, _, err := findMatchingScan(image, results)
	require.ErrorContains(t, err, "multiple released SBOM scans")
	image.Platform = "linux/amd64"
	file, found, err := findMatchingScan(image, results)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, results["amd64"], file)
}

func TestMatchingUsesFullImageIdentity(t *testing.T) {
	dir := t.TempDir()
	image := testIdentity(t, "registry-a.example/team/app:v2", "", "")
	results := map[string]string{
		"app":            writeScanIdentity(t, filepath.Join(dir, "app_v1.json"), testIdentity(t, "registry-a.example/team/app:v1", "linux/amd64", "sha256:app")),
		"helper":         writeScanIdentity(t, filepath.Join(dir, "app_helper_v1.json"), testIdentity(t, "registry-a.example/team/app_helper:v1", "linux/amd64", "sha256:helper")),
		"other registry": writeScanIdentity(t, filepath.Join(dir, "other-app_v1.json"), testIdentity(t, "registry-b.example/team/app:v1", "linux/amd64", "sha256:other")),
	}
	file, found, err := findMatchingScan(image, results)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, results["app"], file)
}

func TestMatchingDeduplicatesEquivalentAliases(t *testing.T) {
	for _, platform := range []string{"", "linux/amd64"} {
		t.Run(platform, func(t *testing.T) {
			dir := t.TempDir()
			image := testIdentity(t, "docker.io/library/app:v2", "", "")
			results := map[string]string{
				"short":     writeScanIdentity(t, filepath.Join(dir, "app_v1--a.json"), testIdentity(t, "app:v1", platform, "sha256:same")),
				"long":      writeScanIdentity(t, filepath.Join(dir, "app_v1--b.json"), testIdentity(t, "index.docker.io/library/app:v1", platform, "sha256:same")),
				"tag alias": writeScanIdentity(t, filepath.Join(dir, "app_latest.json"), testIdentity(t, "registry.hub.docker.com/library/app:latest", platform, "sha256:same")),
			}
			file, found, err := findMatchingScan(image, results)
			require.NoError(t, err)
			require.True(t, found)
			require.NotEmpty(t, file)
			writeScanIdentity(t, results["tag alias"], testIdentity(t, "app:latest", platform, "sha256:different"))
			_, _, err = findMatchingScan(image, results)
			require.ErrorContains(t, err, "multiple released SBOM scans")
		})
	}
}

func TestMatchingAliasesCannotHideConflictingImageIDs(t *testing.T) {
	dir := t.TempDir()
	image := testIdentity(t, "app:v2", "", "")
	results := map[string]string{
		"missing ID": writeScanIdentity(t, filepath.Join(dir, "a.json"), testIdentity(t, "app:v1", "linux/amd64", "")),
		"known ID":   writeScanIdentity(t, filepath.Join(dir, "b.json"), testIdentity(t, "app:v1", "linux/amd64", "sha256:one")),
		"other ID":   writeScanIdentity(t, filepath.Join(dir, "c.json"), testIdentity(t, "app:v1", "linux/amd64", "sha256:two")),
	}
	_, _, err := findMatchingScan(image, results)
	require.ErrorContains(t, err, "multiple released SBOM scans")
}
