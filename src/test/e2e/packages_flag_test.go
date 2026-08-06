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
	stdoutNoFlag, stderrNoFlag, errNoFlag := e2e.UDSPKDir("src/test", "release", "check", "base", "-r", "https://localhost:9090/registry/path", "--verbose")
	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "check", "base", "-p", "", "-r", "https://localhost:9090/registry/path", "--verbose")
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

	e2e.CreateZarfYaml(t, "src/test/sandbox")
	e2e.CreateAltZarfYaml(t, "first", "src/test/sandbox/first")
	e2e.CreateAltZarfYaml(t, "second", "src/test/sandbox/second")
	e2e.CreateUDSBundleYamlMultiPackage(t, "src/test/sandbox/bundle")
	e2e.CreatePackageReleaseConfig(t, "src/test/sandbox",
		releaseTypes.Package{
			Name: "first",
			Path: "first",
			Flavors: []releaseTypes.Flavor{
				{Name: "base", Version: "1.0.0-flag.0"},
			},
		},
		releaseTypes.Package{
			Name: "second",
			Path: "second",
			Flavors: []releaseTypes.Flavor{
				{Name: "base", Version: "2.0.0-flag.0"},
			},
		},
	)

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "update-yaml", "base", "-d", "sandbox", "-p", "first")
	require.NoError(t, err, stdout, stderr)

	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml("src/test/sandbox/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "devel", zarfPackage.Metadata.Version)

	err = e2e.LoadYaml("src/test/sandbox/second/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "devel", zarfPackage.Metadata.Version)

	err = e2e.LoadYaml("src/test/sandbox/first/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-flag.0", zarfPackage.Metadata.Version)

	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-flag.0-base", bundle.Metadata.Version)
	require.Equal(t, "devel", bundle.Packages[0].Ref)
	require.Equal(t, "1.0.0-flag.0-base", bundle.Packages[1].Ref)
	require.Equal(t, "devel", bundle.Packages[2].Ref)
}
