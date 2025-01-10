// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestYQ(t *testing.T) {

	tests := []struct {
		yaml       string
		expression string
		want       string
	}{
		{
			yaml: `
components:
  - name: my-component
    charts:
      - name: uds-app-config
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			expression: ".components[0].charts[0].namespace",
			want:       "mynamespace",
		},
		{
			yaml: `
components:
  - name: my-component
    charts:
      - name: uds-app-config
        namespace: mynamespace2
      - name: app
        namespace: mynamespace3
`,
			expression: ".components[].charts[].namespace",
			want:       "mynamespace2\nmynamespace3",
		},
	}

	for _, tt := range tests {
		tmpDir := t.TempDir()
		yamlPath := filepath.Join(tmpDir, "test.yaml")

		if err := os.WriteFile(yamlPath, []byte(tt.yaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}

		got, _ := EvaluateYqToString(tt.expression, yamlPath)

		require.Equal(t, tt.want, got, fmt.Sprintf("Expected namespace [%s] but got [%s].", tt.want, got))
	}
}
