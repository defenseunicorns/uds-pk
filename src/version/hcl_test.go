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

func TestPrepareNextBundleUpdate(t *testing.T) {
	tests := []struct {
		name            string
		flavor          types.Flavor
		initialHCL      string
		createFile      bool
		oldSource       string
		newSource       string
		expectedVersion string
		expectedError   string
	}{
		{
			name:   "update matching package and preserve other HCL",
			flavor: types.Flavor{Name: "upstream", Version: "1.2.3"},
			initialHCL: `# Keep this comment
uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name    = "test"
  version = "dev"
}

package "application" {
  source = "../zarf-package-test-package-${sys.arch}-dev.tar.zst"
  signature_verification { verify = false }
}

package "remote" {
  source = "oci://registry/app:${sys.arch == "amd64" ? "x86" : "arm"}"
}

package "podinfo" {
  source = "../zarf-package-podinfo-${sys.arch}-dev.tar.zst"
  signature_verification { verify = false }
}

package "test-package-resources" {
  source = "../zarf-package-test-package-resources-${sys.arch}-dev.tar.zst"
  signature_verification { verify = false }
}
`,
			createFile:      true,
			oldSource:       "../zarf-package-test-package-${sys.arch}-dev.tar.zst",
			newSource:       "../zarf-package-test-package-${sys.arch}-1.2.3-upstream.tar.zst",
			expectedVersion: "1.2.3-upstream",
		},
		{
			name:   "flavorless fixed architecture",
			flavor: types.Flavor{Version: "2.0.0"},
			initialHCL: `uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name = "test"
  version = "dev"
}

package "app" {
  source = "../zarf-package-test-package-amd64-dev.tar.zst"
  signature_verification { verify = false }
}
`,
			createFile:      true,
			oldSource:       "../zarf-package-test-package-amd64-dev.tar.zst",
			newSource:       "../zarf-package-test-package-amd64-2.0.0.tar.zst",
			expectedVersion: "2.0.0",
		},
		{
			name:   "architecture word in old version",
			flavor: types.Flavor{Version: "2.0.0"},
			initialHCL: `uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name = "test"
  version = "dev"
}

package "application" {
  source = "../zarf-package-test-package-amd64-1.2.3-arm64-debug.tar.zst"
  signature_verification { verify = false }
}
`,
			createFile:    true,
			expectedError: "ambiguous Zarf archive",
		},
		{
			name:   "ambiguous similarly named package is rejected",
			flavor: types.Flavor{Version: "1.2.3"},
			initialHCL: `uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name = "test"
  version = "dev"
}

package "test-package-arm64" {
  source = "../zarf-package-test-package-arm64-amd64-dev.tar.zst"
  signature_verification { verify = false }
}
`,
			createFile:    true,
			expectedError: "ambiguous Zarf archive",
		},
		{
			name:          "invalid HCL",
			flavor:        types.Flavor{Version: "1.2.3"},
			initialHCL:    "invalid = [",
			createFile:    true,
			expectedError: "parse bundle",
		},
		{
			name:          "file does not exist",
			flavor:        types.Flavor{Version: "1.2.3"},
			expectedError: "read bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			releaseDir := t.TempDir()
			bundleDir := filepath.Join(releaseDir, "bundle")
			require.NoError(t, os.MkdirAll(bundleDir, 0o755))
			bundlePath := filepath.Join(bundleDir, "bundle.uds.hcl")
			if tt.createFile {
				require.NoError(t, os.WriteFile(bundlePath, []byte(tt.initialHCL), 0o640))
			}

			update, err := prepareNextBundleUpdate(tt.flavor, releaseDir, "test-package", false)
			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				require.Nil(t, update)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, update)
			require.Equal(t, bundlePath, update.path)
			require.Equal(t, "bundle.uds.hcl", update.label)
			require.Equal(t, tt.expectedVersion, update.version)
			require.Equal(t, os.FileMode(0o640), update.mode)

			want := strings.Replace(tt.initialHCL, `version = "dev"`, `version = "`+tt.expectedVersion+`"`, 1)
			want = strings.Replace(want, tt.oldSource, tt.newSource, 1)
			require.Equal(t, want, string(update.content))
			require.NoError(t, os.WriteFile(update.path, update.content, update.mode))
			written, err := os.ReadFile(bundlePath)
			require.NoError(t, err)
			require.Equal(t, want, string(written))
		})
	}
}

func TestPrepareNextBundleUpdateLocals(t *testing.T) {
	tests := []struct {
		name          string
		locals        string
		expectedError string
	}{
		{
			name: "source references local version",
			locals: `locals {
  version = "dev"
}`,
		},
		{
			name: "chained locals across blocks",
			locals: `locals {
  version = local.release
}

locals {
  release = local.base
  base = "dev"
}`,
		},
		{
			name: "missing local reference",
			locals: `locals {
  version = local.missing
}`,
			expectedError: "cannot resolve locals: version",
		},
		{
			name: "circular local references",
			locals: `locals {
  version = local.release
  release = local.version
}`,
			expectedError: "cannot resolve locals: release, version",
		},
		{
			name: "duplicate local definitions",
			locals: `locals {
  version = "dev"
}

locals {
  version = "other"
}`,
			expectedError: `duplicate local "version"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			releaseDir := t.TempDir()
			bundleDir := filepath.Join(releaseDir, "bundle")
			require.NoError(t, os.MkdirAll(bundleDir, 0o755))
			bundlePath := filepath.Join(bundleDir, "bundle.uds.hcl")
			original := `uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name = "test-bundle"
  version = "old-bundle"
}

` + tt.locals + `

package "application" {
  source = "../zarf-package-test-package-${sys.arch}-${local.version}.tar.zst"
  signature_verification { verify = false }
}
`
			require.NoError(t, os.WriteFile(bundlePath, []byte(original), 0o640))

			update, err := prepareNextBundleUpdate(
				types.Flavor{Name: "upstream", Version: "1.2.3"}, releaseDir, "test-package", false,
			)
			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				require.Nil(t, update)
			} else {
				require.NoError(t, err)
				require.NotNil(t, update)
				want := strings.Replace(original, `version = "old-bundle"`, `version = "1.2.3-upstream"`, 1)
				want = strings.Replace(want,
					"zarf-package-test-package-${sys.arch}-${local.version}.tar.zst",
					"zarf-package-test-package-${sys.arch}-1.2.3-upstream.tar.zst", 1)
				require.Equal(t, want, string(update.content))
				require.Equal(t, "1.2.3-upstream", update.version)
				require.Equal(t, os.FileMode(0o640), update.mode)
			}

			// Preparing an update must leave the original file untouched.
			unchanged, err := os.ReadFile(bundlePath)
			require.NoError(t, err)
			require.Equal(t, original, string(unchanged))
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

func TestUpdateYamlsPackageScopedNextBundle(t *testing.T) {
	const unrelatedBundle = `uds {
  bundle_api_version = "uds.dev/v1alpha1"
}

metadata {
  name = "root-bundle"
  version = "dev"
}

package "other" {
  source = "../zarf-package-other-${sys.arch}-dev.tar.zst"
}
`
	tests := []struct {
		name               string
		bundle             string
		allowMissingBundle bool
		expectedError      string
	}{
		{
			name:               "optional unrelated bundle is unchanged",
			bundle:             unrelatedBundle,
			allowMissingBundle: true,
		},
		{
			name:          "required bundle still needs a matching source",
			bundle:        unrelatedBundle,
			expectedError: "no local source",
		},
		{
			name:               "optional bundle still reports malformed HCL",
			bundle:             "invalid = [",
			allowMissingBundle: true,
			expectedError:      "parse bundle",
		},
		{
			name:               "optional bundle still requires metadata",
			bundle:             `package "other" { source = "../zarf-package-other-amd64-dev.tar.zst" }`,
			allowMissingBundle: true,
			expectedError:      "no metadata block",
		},
		{
			name:               "optional bundle still requires metadata version",
			bundle:             strings.Replace(unrelatedBundle, "  version = \"dev\"\n", "", 1),
			allowMissingBundle: true,
			expectedError:      "no metadata.version",
		},
		{
			name:               "optional bundle still reports unresolved locals",
			bundle:             unrelatedBundle + "\nlocals { version = local.missing }\n",
			allowMissingBundle: true,
			expectedError:      "cannot resolve locals: version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			releaseDir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(releaseDir, "bundle"), 0o755))
			require.NoError(t, os.MkdirAll(filepath.Join(releaseDir, "child"), 0o755))
			bundlePath := filepath.Join(releaseDir, "bundle", "bundle.uds.hcl")
			zarfPath := filepath.Join(releaseDir, "child", "zarf.yaml")
			originalZarf := "metadata:\n  name: child\n  version: dev\n"
			require.NoError(t, os.WriteFile(bundlePath, []byte(tt.bundle), 0o644))
			require.NoError(t, os.WriteFile(zarfPath, []byte(originalZarf), 0o644))

			err := UpdateYamls(types.Flavor{Version: "1.2.3"}, "child", releaseDir, nil, tt.allowMissingBundle)
			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
			}

			bundleAfter, err := os.ReadFile(bundlePath)
			require.NoError(t, err)
			require.Equal(t, tt.bundle, string(bundleAfter))
			zarfAfter, err := os.ReadFile(zarfPath)
			require.NoError(t, err)
			if tt.expectedError != "" {
				require.Equal(t, originalZarf, string(zarfAfter))
			} else {
				require.Contains(t, string(zarfAfter), "version: 1.2.3")
			}
		})
	}
}

func TestUpdateYamlsDoesNotModifyZarfWhenNextBundleIsInvalid(t *testing.T) {
	releaseDir := t.TempDir()
	bundleDir := filepath.Join(releaseDir, "bundle")
	require.NoError(t, os.MkdirAll(bundleDir, 0o755))
	zarfPath := filepath.Join(releaseDir, "zarf.yaml")
	originalZarf := "metadata:\n  name: test-package\n  version: dev\n"
	require.NoError(t, os.WriteFile(zarfPath, []byte(originalZarf), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(bundleDir, "bundle.uds.hcl"), []byte("invalid = ["), 0o644))

	err := UpdateYamls(types.Flavor{Name: "upstream", Version: "1.2.3"}, "", releaseDir, nil, false)
	require.ErrorContains(t, err, "parse bundle")
	zarf, readErr := os.ReadFile(zarfPath)
	require.NoError(t, readErr)
	require.Equal(t, originalZarf, string(zarf))
}
