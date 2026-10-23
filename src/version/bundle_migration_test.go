// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	uds "github.com/defenseunicorns/uds-cli/pkg/legacy/types"
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/stretchr/testify/require"
)

func TestUpdateYamlsDualFormatFailureLeavesFilesUnchanged(t *testing.T) {
	const next = `uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name = "test-bundle"
  version = "dev"
}

package "application" {
  source = "../zarf-package-test-package-${sys.arch}-dev.tar.zst"
}
`
	const legacy = `metadata:
  name: test-bundle
  version: dev
packages:
  - name: test-package
    ref: dev
`
	tests := []struct {
		name          string
		next          string
		legacy        string
		expectedError string
	}{
		{
			name:          "malformed HCL",
			next:          "invalid = [",
			legacy:        legacy,
			expectedError: "parse bundle",
		},
		{
			name:          "malformed legacy YAML after preparing HCL",
			next:          next,
			legacy:        "invalid: [",
			expectedError: "parse bundle",
		},
		{
			name: "ambiguous source with alias label",
			next: strings.Replace(next,
				"test-package-${sys.arch}-dev", "test-package-arm64-amd64-dev", 1),
			legacy:        legacy,
			expectedError: "ambiguous Zarf archive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			releaseDir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(releaseDir, "bundle"), 0o755))
			require.NoError(t, os.MkdirAll(filepath.Join(releaseDir, "chart"), 0o755))
			files := map[string]string{
				"zarf.yaml":              "metadata:\n  name: test-package\n  version: dev\n",
				"bundle/bundle.uds.hcl":  tt.next,
				"bundle/uds-bundle.yaml": tt.legacy,
				"chart/Chart.yaml":       "apiVersion: v2\nname: test-chart\nversion: 0.1.0\n",
			}
			for name, original := range files {
				require.NoError(t, os.WriteFile(filepath.Join(releaseDir, name), []byte(original), 0o640))
			}

			err := UpdateYamls(types.Flavor{Name: "upstream", Version: "1.2.3"}, "", releaseDir,
				[]types.Chart{{Path: "chart", VersionFromFlavor: true}}, false)
			require.ErrorContains(t, err, tt.expectedError)
			for name, original := range files {
				data, err := os.ReadFile(filepath.Join(releaseDir, name))
				require.NoError(t, err)
				require.Equal(t, original, string(data), "file %s changed", name)
			}
		})
	}
}

func TestUpdateYamlsUpdatesBothBundleFormats(t *testing.T) {
	releaseDir := t.TempDir()
	bundleDir := filepath.Join(releaseDir, "bundle")
	require.NoError(t, os.MkdirAll(bundleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(releaseDir, "zarf.yaml"),
		[]byte("metadata:\n  name: test-package\n  version: dev\n"), 0o644))

	legacyPath := filepath.Join(bundleDir, "uds-bundle.yaml")
	legacy := `metadata:
  name: test-bundle
  version: dev
packages:
  - name: test-package
    ref: dev
  - name: other-package
    ref: unchanged
`
	require.NoError(t, os.WriteFile(legacyPath, []byte(legacy), 0o644))
	nextPath := filepath.Join(bundleDir, "bundle.uds.hcl")
	next := `uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name = "test-bundle"
  version = "dev"
}

package "application" {
  source = "../zarf-package-test-package-${sys.arch}-dev.tar.zst"
  signature_verification { verify = false }
}
`
	require.NoError(t, os.WriteFile(nextPath, []byte(next), 0o644))

	err := UpdateYamls(types.Flavor{Name: "upstream", Version: "1.2.3"}, "", releaseDir, nil, false)
	require.NoError(t, err)

	var legacyAfter uds.UDSBundle
	require.NoError(t, utils.LoadYaml(legacyPath, &legacyAfter))
	require.Equal(t, "1.2.3-upstream", legacyAfter.Metadata.Version)
	require.Len(t, legacyAfter.Packages, 2)
	require.Equal(t, "1.2.3-upstream", legacyAfter.Packages[0].Ref)
	require.Equal(t, "unchanged", legacyAfter.Packages[1].Ref)
	nextAfter, err := os.ReadFile(nextPath)
	require.NoError(t, err)
	want := strings.Replace(next, `version = "dev"`, `version = "1.2.3-upstream"`, 1)
	want = strings.Replace(want,
		"zarf-package-test-package-${sys.arch}-dev.tar.zst",
		"zarf-package-test-package-${sys.arch}-1.2.3-upstream.tar.zst", 1)
	require.Equal(t, want, string(nextAfter))
}
