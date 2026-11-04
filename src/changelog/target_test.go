// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"testing"

	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/stretchr/testify/require"
)

func TestResolveTarget(t *testing.T) {
	config, err := utils.LoadReleaseConfig("testdata")
	require.NoError(t, err)
	tests := []struct {
		name      string
		selection Selection
		want      releaseTarget
	}{
		{
			name: "root flavor", selection: Selection{Flavor: "upstream"},
			want: releaseTarget{Kind: "root", Flavor: "upstream", Version: "1.2.0", Tag: "1.2.0-upstream"},
		},
		{
			name: "root flavorless non-semver", selection: Selection{},
			want: releaseTarget{Kind: "root", Version: "non-semver", Tag: "non-semver"},
		},
		{
			name: "named package flavor", selection: Selection{Package: "api", Flavor: "upstream"},
			want: releaseTarget{Kind: "package", Name: "api", Flavor: "upstream", Version: "2.0.0-uds.1", Tag: "api-2.0.0-uds.1-upstream", Paths: []string{"packages/api", "charts/api"}},
		},
		{
			name: "named package flavorless", selection: Selection{Package: "api"},
			want: releaseTarget{Kind: "package", Name: "api", Version: "2.0.0", Tag: "api-2.0.0", Paths: []string{"packages/api", "charts/api"}},
		},
		{
			name: "second package", selection: Selection{Package: "api-worker"},
			want: releaseTarget{Kind: "package", Name: "api-worker", Version: "3.0.0", Tag: "api-worker-3.0.0", Paths: []string{"packages/api-worker"}},
		},
		{
			name: "bundle", selection: Selection{Bundle: "platform"},
			want: releaseTarget{Kind: "bundle", Name: "platform", Version: "4.0.0", Tag: "platform-4.0.0", Paths: []string{"bundles/platform"}},
		},
		{
			name: "second bundle non-semver", selection: Selection{Bundle: "platform-test"},
			want: releaseTarget{Kind: "bundle", Name: "platform-test", Version: "testing", Tag: "platform-test-testing", Paths: []string{"bundles/platform-test"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := resolveTarget(config, test.selection)
			require.NoError(t, err)
			require.Equal(t, test.want, target)
		})
	}

	t.Run("bundle without root or packages", func(t *testing.T) {
		config.Flavors = nil
		config.Packages = nil
		require.NoError(t, config.VerifyReleaseConfig())
		target, err := resolveTarget(config, Selection{Bundle: "platform"})
		require.NoError(t, err)
		require.Equal(t, "platform-4.0.0", target.Tag)
	})
}

func TestResolveTargetErrors(t *testing.T) {
	config, err := utils.LoadReleaseConfig("testdata")
	require.NoError(t, err)
	tests := []struct {
		selection Selection
		message   string
	}{
		{Selection{Package: "missing"}, "package not found"},
		{Selection{Flavor: "missing"}, "flavor not found"},
		{Selection{Package: "api", Flavor: "missing"}, "flavor not found"},
		{Selection{Bundle: "missing"}, "bundle missing is not defined"},
		{Selection{Bundle: "platform", Package: "api"}, "cannot be combined"},
		{Selection{Bundle: "platform", Flavor: "upstream"}, "cannot be combined"},
	}
	for _, test := range tests {
		target, err := resolveTarget(config, test.selection)
		require.ErrorContains(t, err, test.message)
		require.Empty(t, target)
	}
}
