// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	uds "github.com/defenseunicorns/uds-cli/pkg/legacy/types"
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

func TestHCLBundleUpdateMetadataConsistency(t *testing.T) {
	const version = "release-${literal}-%{literal}-\"quoted\""
	for _, tt := range []struct {
		name, metadata, wantError string
	}{
		{name: "escaped version", metadata: "metadata { version = local.version }"},
		{name: "missing metadata", wantError: "no metadata block"},
		{name: "missing version", metadata: "metadata { name = \"example\" }", wantError: "no metadata.version"},
		{name: "duplicate metadata", metadata: "metadata { version = \"old\" }\nmetadata { version = \"other\" }", wantError: "exactly one metadata block"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bundleDir := filepath.Join(dir, "bundle")
			require.NoError(t, os.Mkdir(bundleDir, 0o755))
			filename := filepath.Join(bundleDir, "bundle.uds.hcl")
			original := tt.metadata + "\npackage \"app\" { source = \"../zarf-package-app-amd64-old.tar.zst\" }\n"
			require.NoError(t, os.WriteFile(filename, []byte(original), 0o640))
			metadataOnly, metadataErr := replaceBundleMetadataVersion([]byte(original), filename, version)
			update, packageErr := prepareNextBundleUpdate(types.Flavor{Version: version}, dir, "app", false)
			if tt.wantError != "" {
				require.ErrorContains(t, metadataErr, tt.wantError)
				require.ErrorContains(t, packageErr, tt.wantError)
				require.Nil(t, update)
				return
			}
			require.NoError(t, metadataErr)
			require.NoError(t, packageErr)
			for _, data := range [][]byte{metadataOnly, update.content} {
				parsed, diags := hclsyntax.ParseConfig(data, filename, hcl.InitialPos)
				require.False(t, diags.HasErrors(), diags.Error())
				body := parsed.Body.(*hclsyntax.Body)
				value, diags := body.Blocks[0].Body.Attributes["version"].Expr.Value(nil)
				require.False(t, diags.HasErrors(), diags.Error())
				require.Equal(t, version, value.AsString())
			}
			require.Contains(t, string(metadataOnly), "zarf-package-app-amd64-old.tar.zst")
			parsed, diags := hclsyntax.ParseConfig(update.content, filename, hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			source, diags := parsed.Body.(*hclsyntax.Body).Blocks[1].Body.Attributes["source"].Expr.Value(nil)
			require.False(t, diags.HasErrors(), diags.Error())
			require.Equal(t, "../zarf-package-app-amd64-"+version+".tar.zst", source.AsString())
		})
	}
}

func TestUpdateBundleYAMLFormats(t *testing.T) {
	const originalHCL = `# Bundle notes
locals { version = file("version.txt") }
metadata {
  name    = "example"
  version = local.version # keep this comment
}
package "app" {
  source = "oci://example.com/app:old"
}
`
	const originalYAML = "metadata:\n  name: example\n  version: old\npackages:\n  - name: app\n    ref: old\n"
	for _, format := range []string{"HCL", "YAML", "both"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			bundle := types.Bundle{Name: "example", Path: "bundles/nested/example", Version: "2.0.0-uds.1"}
			path := filepath.Join(dir, bundle.Path)
			require.NoError(t, os.MkdirAll(path, 0o755))
			originals := map[string]string{}
			if format != "YAML" {
				originals["bundle.uds.hcl"] = originalHCL
			}
			if format != "HCL" {
				originals["uds-bundle.yaml"] = originalYAML
			}
			for filename, original := range originals {
				require.NoError(t, os.WriteFile(filepath.Join(path, filename), []byte(original), 0o640))
			}
			require.NoError(t, UpdateBundleYAML(bundle, dir))
			for filename := range originals {
				info, err := os.Stat(filepath.Join(path, filename))
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
				if filename == "bundle.uds.hcl" {
					data, err := os.ReadFile(filepath.Join(path, filename))
					require.NoError(t, err)
					require.Equal(t, strings.Replace(originalHCL, "version = local.version", `version = "2.0.0-uds.1"`, 1), string(data))
				} else {
					var actual uds.UDSBundle
					require.NoError(t, utils.LoadYaml(filepath.Join(path, filename), &actual))
					require.Equal(t, bundle.Version, actual.Metadata.Version)
					require.Equal(t, "old", actual.Packages[0].Ref)
				}
			}
			if format == "HCL" {
				require.NoFileExists(t, filepath.Join(path, "uds-bundle.yaml"))
			}
			if format == "YAML" {
				require.NoFileExists(t, filepath.Join(path, "bundle.uds.hcl"))
			}
		})
	}
}

func TestUpdateBundleYAMLFailures(t *testing.T) {
	const validHCL = "metadata { version = \"old\" }\n"
	const validYAML = "metadata:\n  version: old\n"
	for _, tt := range []struct {
		name, hcl, yaml, wantError string
		failWrite                  bool
	}{
		{name: "absent", wantError: "neither"},
		{name: "malformed HCL", hcl: "invalid = [", yaml: validYAML, wantError: "parse bundle"},
		{name: "malformed YAML", hcl: validHCL, yaml: "invalid: [", wantError: "update bundle"},
		{name: "missing metadata", hcl: "locals { version = \"old\" }", yaml: validYAML, wantError: "no metadata block"},
		{name: "duplicate metadata", hcl: validHCL + validHCL, yaml: validYAML, wantError: "exactly one metadata"},
		{name: "missing version", hcl: "metadata { name = \"example\" }", yaml: validYAML, wantError: "no metadata.version"},
		{name: "write failure", hcl: validHCL, yaml: validYAML, wantError: "forced write failure", failWrite: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			originals := map[string]string{}
			if tt.hcl != "" {
				originals["bundle.uds.hcl"] = tt.hcl
			}
			if tt.yaml != "" {
				originals["uds-bundle.yaml"] = tt.yaml
			}
			for filename, original := range originals {
				require.NoError(t, os.WriteFile(filepath.Join(dir, filename), []byte(original), 0o640))
			}
			if tt.failWrite {
				originalWrite := writeFileInPlace
				t.Cleanup(func() { writeFileInPlace = originalWrite })
				calls := 0
				writeFileInPlace = func(path string, data []byte) error {
					calls++
					if calls == 2 {
						require.NoError(t, originalWrite(path, []byte("partial write")))
						return fmt.Errorf("forced write failure")
					}
					return originalWrite(path, data)
				}
			}
			require.ErrorContains(t, UpdateBundleYAML(types.Bundle{Version: "2.0.0"}, dir), tt.wantError)
			for filename, original := range originals {
				data, err := os.ReadFile(filepath.Join(dir, filename))
				require.NoError(t, err)
				require.Equal(t, original, string(data))
			}
		})
	}
}

func TestReplaceBundleMetadataVersionEscapesHCL(t *testing.T) {
	const version = "release-${literal}-%{literal}-\"quoted\""
	data, err := replaceBundleMetadataVersion([]byte("metadata { version = \"old\" }"), "bundle.uds.hcl", version)
	require.NoError(t, err)
	parsed, diags := hclsyntax.ParseConfig(data, "bundle.uds.hcl", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	value, diags := parsed.Body.(*hclsyntax.Body).Blocks[0].Body.Attributes["version"].Expr.Value(nil)
	require.False(t, diags.HasErrors(), diags.Error())
	require.Equal(t, version, value.AsString())
}
