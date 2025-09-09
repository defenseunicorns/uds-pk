// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"testing"

	uds "github.com/defenseunicorns/uds-cli/src/types"
	"github.com/stretchr/testify/require"
	zarf "github.com/zarf-dev/zarf/src/api/v1alpha1"
)

func TestPackageFlagCheck(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("release", "check", "base", "-d", "src/test", "-p", "first")
	require.NoError(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version first-1.0.0-flag.0-base is not tagged")

	stdout, stderr, err = e2e.UDSPK("release", "check", "base", "-d", "src/test", "-p", "second")
	require.NoError(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version second-2.0.0-flag.0-base is not tagged")

	stdout, stderr, err = e2e.UDSPK("release", "check", "dummy", "-d", "src/test", "-p", "dummy")
	require.Error(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version dummy-testing-dummy is already tagged")
}

func TestPackageFlagShow(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "show", "base", "-p", "first")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "1.0.0-flag.0-base\n", stdout)

	stdout, stderr, err = e2e.UDSPKDir("src/test", "release", "show", "base", "--version-only", "-p", "first")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "1.0.0-flag.0\n", stdout)
}

func TestFlagsWithEmptyStrings(t *testing.T) {
	// Test that the flags can be used with empty strings
	stdoutNoFlag, stderrNoFlag, errNoFlag := e2e.UDSPK("release", "check", "base", "-d", "src/test")
	stdout, stderr, err := e2e.UDSPK("release", "check", "base", "-d", "src/test", "-p", "")
	require.Equal(t, stdoutNoFlag, stdout)
	require.Equal(t, stderrNoFlag, stderr)
	require.Equal(t, errNoFlag, err)

	stdoutNoFlag, stderrNoFlag, errNoFlag = e2e.UDSPK("release", "show", "base", "-d", "src/test")
	stdout, stderr, err = e2e.UDSPK("release", "show", "base", "-d", "src/test", "-p", "")
	require.Equal(t, stdoutNoFlag, stdout)
	require.Equal(t, stderrNoFlag, stderr)
	require.Equal(t, errNoFlag, err)
}

func TestPackageFlagUpdateYaml(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle", "first", "second")
	defer e2e.CleanupSandboxDir(t)

	// Create a dummy zarf yaml with devel as version
	e2e.CreateZarfYaml(t, "src/test/sandbox")

	// Create first alt dummy zarf yaml with devel as version
	e2e.CreateAltZarfYaml(t, "first", "src/test/sandbox/first")

	// Create second alt dummy zarf yaml with devel as version
	e2e.CreateAltZarfYaml(t, "second", "src/test/sandbox/second")

	// Create a dummy uds-bundle yaml with devel as version
	e2e.CreateUDSBundleYamlMultiPackage(t, "src/test/sandbox/bundle")

	stdout, stderr, err := e2e.UDSPKDir("src/test/sandbox", "release", "update-yaml", "base", "-d", "../", "-p", "first")
	require.NoError(t, err, stdout, stderr)

	// Check that the base zarf.yaml wasn't updated
	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml("src/test/sandbox/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "devel", zarfPackage.Metadata.Version)

	// Check that the second zarf.yaml wasn't updated
	err = e2e.LoadYaml("src/test/sandbox/second/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "devel", zarfPackage.Metadata.Version)

	// Check that the first zarf.yaml was updated
	err = e2e.LoadYaml("src/test/sandbox/first/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-flag.0", zarfPackage.Metadata.Version)

	// Check that the uds-bundle.yaml was updated
	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-flag.0-base", bundle.Metadata.Version)
	require.Equal(t, "devel", bundle.Packages[0].Ref)
	require.Equal(t, "1.0.0-flag.0-base", bundle.Packages[1].Ref)
	require.Equal(t, "devel", bundle.Packages[2].Ref)
}
