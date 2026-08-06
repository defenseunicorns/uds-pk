// Copyright 2024-2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"testing"

	uds "github.com/defenseunicorns/uds-cli/src/types"
	releaseTypes "github.com/defenseunicorns/uds-pk/src/types"
	"github.com/stretchr/testify/require"
	zarf "github.com/zarf-dev/zarf/src/api/v1alpha1"
)

func TestFlavorlessShow(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "show")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "1.0.0-flavorless.0\n", stdout)

	stdout, stderr, err = e2e.UDSPKDir("src/test", "release", "show", "-p", "dummy")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "flavorless-testing\n", stdout)
}

func TestFlavorlessUpdateYaml(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle")
	defer e2e.CleanupSandboxDir(t)

	e2e.CreateZarfYaml(t, "src/test/sandbox")
	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle")
	e2e.CreateFlavorReleaseConfig(t, "src/test/sandbox",
		releaseTypes.Flavor{Name: "base", Version: "1.0.0-uds.0"},
		releaseTypes.Flavor{Version: "1.0.0-flavorless.0"},
	)

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "update-yaml", "-d", "sandbox")
	require.NoError(t, err, stdout, stderr)

	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml("src/test/sandbox/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-flavorless.0", zarfPackage.Metadata.Version)

	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-flavorless.0", bundle.Metadata.Version)
	require.Equal(t, "1.0.0-flavorless.0", bundle.Packages[0].Ref)
}
