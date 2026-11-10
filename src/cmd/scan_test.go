// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/require"
)

func TestFlavorlessReleaseSelection(t *testing.T) {
	original := FetchPackageFlavor
	t.Cleanup(func() { FetchPackageFlavor = original })
	version := func(tags ...string) *github.PackageVersion {
		metadata, err := json.Marshal(map[string]any{"container": map[string]any{"tags": tags}})
		require.NoError(t, err)
		return &github.PackageVersion{Metadata: metadata}
	}
	for _, releaseTag := range []string{"1.0.0", "1.0.0-uds.0", "1.0.0-rc1", "custom-release"} {
		t.Run(releaseTag, func(t *testing.T) {
			var checked []string
			FetchPackageFlavor = func(owner, pkg, tag string) (string, error) {
				require.Equal(t, "test", owner)
				require.Equal(t, "app", pkg)
				checked = append(checked, tag)
				if tag == releaseTag {
					return "", nil
				}
				require.Equal(t, "2.0.0-upstream", tag)
				return "upstream", nil
			}
			versions := []PackageWithVersion{{encodedPackageUrl: "app", versions: []*github.PackageVersion{
				version("sha256-deadbeef.sig", "sha256-deadbeef.att", "sha256-deadbeef.sbom"),
				version("2.0.0-upstream", "latest"),
				version(releaseTag),
			}}}
			tag, pkg, err := findNewestTagForFlavor(versions, "", "test", slog.Default())
			require.NoError(t, err)
			require.Equal(t, releaseTag, tag)
			require.Equal(t, "app", pkg)
			require.Equal(t, []string{"2.0.0-upstream", releaseTag}, checked)
		})
	}
	FetchPackageFlavor = func(_, _, _ string) (string, error) { return "", errors.New("unreadable metadata") }
	_, _, err := findNewestTagForFlavor([]PackageWithVersion{{versions: []*github.PackageVersion{version("1.0.0")}}}, "", "test", slog.Default())
	require.ErrorContains(t, err, "unreadable metadata")
	FetchPackageFlavor = func(_, _, _ string) (string, error) {
		t.Fatal("named flavor selection must not inspect unrelated metadata")
		return "", nil
	}
	tag, _, err := findNewestTagForFlavor([]PackageWithVersion{{versions: []*github.PackageVersion{version("1.0.0-notupstream", "1.0.0-upstream")}}}, "upstream", "test", slog.Default())
	require.NoError(t, err)
	require.Equal(t, "1.0.0-upstream", tag)
}
