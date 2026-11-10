// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package platforms

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/stretchr/testify/require"
)

type componentReleaseRecorder struct {
	t      *testing.T
	source string
	called bool
}

func (p *componentReleaseRecorder) TagAndRelease(flavor types.Flavor, tokenVar, packageName string) error {
	p.called = true
	require.Equal(p.t, p.source, flavor.Source)
	require.Equal(p.t, "upstream", flavor.Name)
	require.Equal(p.t, "2.0.0", flavor.Version)
	require.Equal(p.t, "RELEASE_TEST_TOKEN", tokenVar)
	require.Equal(p.t, "selected-component", packageName)
	name, err := utils.GetSourceName(flavor.Source)
	require.NoError(p.t, err)
	require.Equal(p.t, "actual-component", name)
	return nil
}

func (p *componentReleaseRecorder) BundleTagAndRelease(types.Bundle, string) error {
	p.t.Fatal("component release must not create a bundle release")
	return nil
}

func TestComponentReleaseUsesSelectedSource(t *testing.T) {
	t.Setenv("RELEASE_TEST_TOKEN", "test-token")
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "components"), 0o755))
	source := filepath.Join(dir, "components", "upstream.yaml")
	require.NoError(t, os.WriteFile(source, []byte("apiVersion: zarf.dev/v1beta1\nkind: ZarfComponentConfig\nmetadata: {name: actual-component}\nvariant: {flavor: upstream}\ncomponent: {}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "releaser.yaml"), []byte("packages:\n  - name: selected-component\n    path: components\n    flavors:\n      - name: upstream\n        version: 2.0.0\n        source: upstream.yaml\n"), 0o644))
	platform := &componentReleaseRecorder{t: t, source: source}
	require.NoError(t, LoadAndTag(dir, "upstream", "RELEASE_TEST_TOKEN", platform, "selected-component"))
	require.True(t, platform.called)
}
