// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/types"
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

func TestPrepareNextBundleUpdateRejectsAmbiguousAliases(t *testing.T) {
	for _, label := range []string{"application", "foo", "foo-arm64"} {
		for _, optional := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/optional=%t", label, optional), func(t *testing.T) {
				releaseDir := t.TempDir()
				require.NoError(t, os.MkdirAll(filepath.Join(releaseDir, "bundle"), 0o755))
				bundle := fmt.Sprintf(`metadata {
  name = "test-bundle"
  version = "dev"
}

package %q {
  source = "../zarf-package-foo-arm64-amd64-dev.tar.zst"
}
`, label)
				require.NoError(t, os.WriteFile(filepath.Join(releaseDir, "bundle", "bundle.uds.hcl"), []byte(bundle), 0o644))
				update, err := prepareNextBundleUpdate(types.Flavor{Version: "1.2.3"}, releaseDir, "foo", optional)
				require.ErrorContains(t, err, "ambiguous Zarf archive")
				require.Nil(t, update)
			})
		}
	}
}

func TestSourceArchitecture(t *testing.T) {
	tests := []struct {
		filename    string
		packageName string
		arch        string
		matched     bool
		ambiguous   bool
	}{
		{"zarf-package-foo-amd64-dev.tar.zst", "foo", "amd64", true, false},
		{"zarf-package-foo-arm64-dev.tar.zst", "foo", "arm64", true, false},
		{"zarf-package-foo-${sys.arch}-dev.tar.zst", "foo", "${sys.arch}", true, false},
		{"zarf-package-foo-resources-amd64-dev.tar.zst", "foo", "", false, false},
		{"zarf-package-foo-resources-amd64-dev.tar.zst", "foo-resources", "amd64", true, false},
		{"zarf-package-foo-arm64-amd64-dev.tar.zst", "foo", "", false, true},
		{"zarf-package-foo-arm64-amd64-dev.tar.zst", "foo-arm64", "", false, true},
		{"zarf-package-foo-${sys.arch}-arm64-dev.tar.zst", "foo", "", false, true},
		{"zarf-package-foo-amd64-1.2.3-arm64-debug.tar.zst", "foo", "", false, true},
		{"zarf-package-foo-amd64-.tar.zst", "foo", "", false, false},
		{"zarf-package-foo-amd64-dev.zip", "foo", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.filename+"/"+tt.packageName, func(t *testing.T) {
			arch, matched, err := sourceArchitecture(tt.filename, tt.packageName)
			if tt.ambiguous {
				require.ErrorContains(t, err, "ambiguous Zarf archive")
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.arch, arch)
			require.Equal(t, tt.matched, matched)
		})
	}
}
