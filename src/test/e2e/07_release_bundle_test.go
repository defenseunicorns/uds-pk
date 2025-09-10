// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"testing"

	uds "github.com/defenseunicorns/uds-cli/src/types"
	"github.com/stretchr/testify/require"
)

// func TestUpdateYamlBundleCommand(t *testing.T) {
// 	e2e.CreateSandboxDir(t, "bundle1", "bundle2")
// 	defer e2e.CleanupSandboxDir(t)

// 	// Create 1st dummy uds-bundle yaml with devel as version
// 	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle1")

// 	// Create 2nd dummy uds-bundle yaml with devel as version
// 	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle2")

// 	stdout, stderr, err := e2e.UDSPKDir("src/test/sandbox", "release", "update-yaml", "-d", "../", "--bundle", "bundle1")
// 	require.NoError(t, err, stdout, stderr)

// 	// Check that the first uds-bundle.yaml was updated
// 	var bundle uds.UDSBundle
// 	err = e2e.LoadYaml("src/test/sandbox/bundle1/uds-bundle.yaml", &bundle)
// 	require.NoError(t, err)

// 	require.Equal(t, "1.0.0-bundle.0", bundle.Metadata.Version)

// 	// Check that the second uds-bundle.yaml wasn't updated
// 	var bundle2 uds.UDSBundle
// 	err = e2e.LoadYaml("src/test/sandbox/bundle2/uds-bundle.yaml", &bundle2)
// 	require.NoError(t, err)

// 	require.Equal(t, "devel", bundle2.Metadata.Version)

// 	stdout, stderr, err = e2e.UDSPKDir("src/test/sandbox", "release", "update-yaml", "-d", "../", "--bundle", "bundle2")
// 	require.NoError(t, err, stdout, stderr)

// 	// Check that the second uds-bundle.yaml was updated
// 	err = e2e.LoadYaml("src/test/sandbox/bundle2/uds-bundle.yaml", &bundle2)
// 	require.NoError(t, err)

// 	require.Equal(t, "2.0.0-bundle.0", bundle2.Metadata.Version)
// }

// func TestUpdateYamlOnlyPackage(t *testing.T) {
// 	e2e.CreateSandboxDir(t, "bundle")
// 	defer e2e.CleanupSandboxDir(t)

// 	// Create a dummy zarf yaml with devel as version
// 	e2e.CreateZarfYaml(t, "src/test/sandbox")

// 	// Create dummy uds-bundle yaml with devel as version
// 	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle")

// 	stdout, stderr, err := e2e.UDSPKDir("src/test/sandbox", "release", "update-yaml", "base", "-d", "../", "--package-only")
// 	require.NoError(t, err, stdout, stderr)

// 	// Check that the zarf.yaml was updated
// 	var zarfPackage zarf.ZarfPackage
// 	err = e2e.LoadYaml("src/test/sandbox/zarf.yaml", &zarfPackage)
// 	require.NoError(t, err)

// 	require.Equal(t, "1.0.0-uds.0", zarfPackage.Metadata.Version)

// 	// Check that the uds-bundle.yaml wasn't updated
// 	var bundle uds.UDSBundle
// 	err = e2e.LoadYaml("src/test/sandbox/bundle/uds-bundle.yaml", &bundle)
// 	require.NoError(t, err)

// 	require.Equal(t, "devel", bundle.Metadata.Version)
// 	require.Equal(t, "devel", bundle.Packages[0].Ref)
// }

func TestBundleShowCommand(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle1")
	defer e2e.CleanupSandboxDir(t)

	// Create dummy uds-bundle yaml with devel as version
	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle1")

	stdout, stderr, err := e2e.UDSPKDir("src/test/sandbox", "release", "bundle", "show", "bundle1", "-d", "../")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "1.0.0-bundle.0\n", stdout)
}

func TestBundleShowCommandTagFlag(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle1")
	defer e2e.CleanupSandboxDir(t)

	// Create dummy uds-bundle yaml with devel as version
	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle1")

	stdout, stderr, err := e2e.UDSPKDir("src/test/sandbox", "release", "bundle", "show", "bundle1", "-d", "../", "--tag")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "bundle1-1.0.0-bundle.0\n", stdout)
}

func TestBundleCheckCommand(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("release", "bundle", "check", "bundle1", "-d", "src/test")
	require.NoError(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version bundle1-1.0.0-bundle.0 is not tagged")

	stdout, stderr, err = e2e.UDSPK("release", "bundle", "check", "dummy", "-d", "src/test")
	require.Error(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version dummy-bundle-testing-dummy is already tagged")
}

func TestBundleCheckCommandBool(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("release", "bundle", "check", "bundle1", "-d", "src/test", "-b")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "true\n", stdout)

	stdout, stderr, err = e2e.UDSPK("release", "bundle", "check", "dummy", "-d", "src/test", "-b")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "false\n", stdout)
}

func TestBundleUpdateYamlCommand(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle1")
	defer e2e.CleanupSandboxDir(t)

	// Create dummy uds-bundle yaml with devel as version
	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle1")

	stdout, stderr, err := e2e.UDSPKDir("src/test/sandbox", "release", "bundle", "update-yaml", "bundle1", "-d", "../")
	require.NoError(t, err, stdout, stderr)

	// Check that the uds-bundle.yaml was updated
	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle1/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-bundle.0", bundle.Metadata.Version)
}
