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
	"github.com/defenseunicorns/uds-pk/src/zarf"
	"github.com/stretchr/testify/require"
)

func TestUpdateStandaloneComponent(t *testing.T) {
	const source = `# reusable component
apiVersion: zarf.dev/v1beta1
kind: ZarfComponentConfig
metadata:
  name: app-component
  version: old # retain version note
variant: {flavor: upstream, architecture: arm64}
values: {files: [values.yaml]}
component:
  import:
    local: [{path: shared.yaml}]
  images: [{name: example.com/app:v1, id: app}]
`
	for _, scoped := range []bool{false, true} {
		t.Run(fmt.Sprintf("scoped=%t", scoped), func(t *testing.T) {
			dir := t.TempDir()
			packagePath := ""
			if scoped {
				packagePath = "components/app"
			}
			componentDir := filepath.Join(dir, packagePath)
			require.NoError(t, os.MkdirAll(componentDir, 0o755))
			require.NoError(t, os.Mkdir(filepath.Join(dir, "bundle"), 0o755))
			componentPath := filepath.Join(componentDir, "upstream.yaml")
			require.NoError(t, os.WriteFile(componentPath, []byte(source), 0o640))
			for _, file := range []string{"zarf.yaml", "bundle/uds-bundle.yaml", "bundle/bundle.uds.hcl"} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, file), []byte("unrelated source\n"), 0o644))
			}
			flavor := types.Flavor{Name: "upstream", Version: "2.0.0", Source: "upstream.yaml"}
			require.NoError(t, UpdateYamls(flavor, packagePath, dir, nil, scoped))
			data, err := os.ReadFile(componentPath)
			require.NoError(t, err)
			require.Equal(t, strings.Replace(source, "version: old", "version: 2.0.0", 1), string(data))
			for _, file := range []string{"zarf.yaml", "bundle/uds-bundle.yaml", "bundle/bundle.uds.hcl"} {
				data, err := os.ReadFile(filepath.Join(dir, file))
				require.NoError(t, err)
				require.Equal(t, "unrelated source\n", string(data))
			}
			info, err := os.Stat(componentPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
			_, err = zarf.Parse([]byte(source))
			require.ErrorContains(t, err, "not supported for package scanning")
			badFlavor := flavor
			badFlavor.Name = "unicorn"
			require.ErrorContains(t, UpdateYamls(badFlavor, packagePath, dir, nil, scoped), "variant flavor")
			before, err := os.ReadFile(componentPath)
			require.NoError(t, err)
			require.Error(t, UpdateYamls(flavor, packagePath, dir, []types.Chart{{Path: "missing-chart", Version: "3.0.0"}}, scoped))
			after, err := os.ReadFile(componentPath)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}
