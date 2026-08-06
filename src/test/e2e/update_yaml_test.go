// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"os"
	"path/filepath"
	"testing"

	uds "github.com/defenseunicorns/uds-cli/src/types"
	"github.com/stretchr/testify/require"
	zarf "github.com/zarf-dev/zarf/src/api/v1alpha1"
)

func TestUpdateYamlCommand(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle")
	defer e2e.CleanupSandboxDir(t)

	e2e.CreateZarfYaml(t, "src/test/sandbox")
	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle")
	e2e.CreateReleaseConfig(t, "src/test/sandbox", `flavors:
  - name: base
    version: "1.0.0-uds.0"
  - version: "1.0.0-flavorless.0"
`)

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "update-yaml", "base", "-d", "sandbox")
	require.NoError(t, err, stdout, stderr)

	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml("src/test/sandbox/zarf.yaml", &zarfPackage)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-uds.0", zarfPackage.Metadata.Version)

	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-uds.0-base", bundle.Metadata.Version)
	require.Equal(t, "1.0.0-uds.0-base", bundle.Packages[0].Ref)
}

func TestUpdateYamlCommandPackageOnlyRepoWithoutBundle(t *testing.T) {
	e2e.CreateSandboxDir(t)
	defer e2e.CleanupSandboxDir(t)

	packageDir := filepath.Join("src/test/sandbox", "packages", "example")
	require.NoError(t, os.MkdirAll(packageDir, 0o755))
	e2e.CreateAltZarfYaml(t, "example", packageDir)
	e2e.CreateReleaseConfig(t, "src/test/sandbox", `packages:
  - name: example
    path: packages/example
    flavors:
      - name: upstream
        version: "1.0.0"
`)

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "update-yaml", "upstream", "-d", "sandbox", "-p", "example")
	require.NoError(t, err, stdout, stderr)

	var zarfPackage zarf.ZarfPackage
	err = e2e.LoadYaml(filepath.Join(packageDir, "zarf.yaml"), &zarfPackage)
	require.NoError(t, err)
	require.Equal(t, "1.0.0", zarfPackage.Metadata.Version)
}
