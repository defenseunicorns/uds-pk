// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	uds "github.com/defenseunicorns/uds-cli/pkg/legacy/types"
	releaseTypes "github.com/defenseunicorns/uds-pk/src/types"
	"github.com/stretchr/testify/require"
)

func TestBundleUpdateYamlCommandHCL(t *testing.T) {
	const original = `# Preserve bundle formatting
locals { notes = file("notes.txt") }
metadata {
  name = "bundle1"
  version = local.version # release version
}
package "app" {
  source = "oci://example.com/app:old"
}
`
	for _, both := range []bool{false, true} {
		name := "HCL only"
		if both {
			name = "both formats"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			bundleDir := filepath.Join(dir, "bundles", "bundle1")
			require.NoError(t, os.MkdirAll(bundleDir, 0o755))
			hclPath := filepath.Join(bundleDir, "bundle.uds.hcl")
			require.NoError(t, os.WriteFile(hclPath, []byte(original), 0o640))
			if both {
				e2e.CreateUDSBundleYaml(t, bundleDir)
			}
			e2e.WriteReleaseConfig(t, dir, releaseTypes.ReleaseConfig{
				Bundles: []releaseTypes.Bundle{{Name: "bundle1", Path: "bundles/bundle1", Version: "2.0.0-bundle.1"}},
			})
			stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "bundle", "update-yaml", "bundle1", "--dir", dir)
			require.NoError(t, err, stdout, stderr)
			require.Contains(t, stdout, "Updated bundle.uds.hcl with version 2.0.0-bundle.1")
			data, err := os.ReadFile(hclPath)
			require.NoError(t, err)
			require.Equal(t, strings.Replace(original, "version = local.version", `version = "2.0.0-bundle.1"`, 1), string(data))
			if both {
				require.Contains(t, stdout, "Updated uds-bundle.yaml with version 2.0.0-bundle.1")
				var bundle uds.UDSBundle
				require.NoError(t, e2e.LoadYaml(filepath.Join(bundleDir, "uds-bundle.yaml"), &bundle))
				require.Equal(t, "2.0.0-bundle.1", bundle.Metadata.Version)
			} else {
				require.NoFileExists(t, filepath.Join(bundleDir, "uds-bundle.yaml"))
			}
		})
	}
}

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
	e2e.WriteReleaseConfig(t, "src/test/sandbox", releaseTypes.ReleaseConfig{
		Bundles: []releaseTypes.Bundle{
			{Name: "bundle1", Path: "bundle1", Version: "1.0.0-bundle.0"},
		},
	})

	stdout, stderr, err := e2e.UDSPKDir("src/test/sandbox", "release", "bundle", "update-yaml", "bundle1", "-d", ".")
	require.NoError(t, err, stdout, stderr)

	// Check that the uds-bundle.yaml was updated
	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle1/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "1.0.0-bundle.0", bundle.Metadata.Version)
}

func TestBundleUpdateYamlCommandUsesReleaseDir(t *testing.T) {
	e2e.CreateSandboxDir(t, "bundle1")
	defer e2e.CleanupSandboxDir(t)

	e2e.CreateUDSBundleYaml(t, "src/test/sandbox/bundle1")
	e2e.WriteReleaseConfig(t, "src/test/sandbox", releaseTypes.ReleaseConfig{
		Bundles: []releaseTypes.Bundle{
			{Name: "bundle1", Path: "bundle1", Version: "2.0.0"},
		},
	})

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "bundle", "update-yaml", "bundle1", "-d", "sandbox")
	require.NoError(t, err, stdout, stderr)

	var bundle uds.UDSBundle
	err = e2e.LoadYaml("src/test/sandbox/bundle1/uds-bundle.yaml", &bundle)
	require.NoError(t, err)

	require.Equal(t, "2.0.0", bundle.Metadata.Version)
}
