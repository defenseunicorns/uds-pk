package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// const TEST_ROOT = "../../src/test/verify"

func TestReadNamespace(t *testing.T) {

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

		got, _ := getNamespaceFromZarfYaml(zarfYamlPath)

		require.Equal(t, tt.want, got, fmt.Sprintf("Expected namespace [%s] but got [%s].", tt.want, got))
	}
}
