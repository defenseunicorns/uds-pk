// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"testing"

	uds "github.com/defenseunicorns/uds-cli/src/types"
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

func TestFlavorlessCheck(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("release", "check", "-d", "src/test")
	require.NoError(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version 1.0.0-flavorless.0 is not tagged")

	stdout, stderr, err = e2e.UDSPK("release", "check", "-d", "src/test", "-p", "dummy")
	require.Error(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version dummy-flavorless-testing is already tagged")
}

func TestFlavorlessUpdateYaml(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle")
	defer e2e.CleanupSandboxDir(t)

	// Create a dummy zarf yaml with devel as version
	e2e.CreateZarfYaml(t, "src/test/sandbox")
	// Create a dummy uds-bundle yaml with devel as version
	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle")

	stdout, stderr, err := e2e.UDSPKDir("src/test/sandbox", "release", "update-yaml", "-d", "../")
	require.NoError(t, err, stdout, stderr)

	// Check that the zarf.yaml was updated
	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml("src/test/sandbox/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-flavorless.0", zarfPackage.Metadata.Version)

	// Check that the uds-bundle.yaml was updated
	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-flavorless.0", bundle.Metadata.Version)
	require.Equal(t, "1.0.0-flavorless.0", bundle.Packages[0].Ref)
}