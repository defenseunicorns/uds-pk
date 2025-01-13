// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/stretchr/testify/require"
)

func TestReadNamespace(t *testing.T) { //TODO (@ewyles) -- rework this to test more specific validations on sample files

	tests := []struct {
		yaml string
		want string
	}{
		{
			yaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			want: "mynamespace",
		},
		{
			yaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace2
      - name: app
        namespace: mynamespace3
`,
			want: "mynamespace2",
		},
	}

	for _, tt := range tests {
		tmpDir := t.TempDir()
		zarfYamlPath := filepath.Join(tmpDir, "zarf.yaml")

		if err := os.WriteFile(zarfYamlPath, []byte(tt.yaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}

		got, _ := utils.EvaluateYqToString(NamespaceExpression, zarfYamlPath)

		require.Equal(t, tt.want, got, fmt.Sprintf("Expected namespace [%s] but got [%s].", tt.want, got))
	}
}
