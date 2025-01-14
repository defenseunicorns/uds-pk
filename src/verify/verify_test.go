// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package verify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckForManifests(t *testing.T) {
	type wantResult struct {
		errorCount   int
		warnCount    int
		successCount int
	}
	tests := []struct {
		yaml string
		want wantResult
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
			want: wantResult{errorCount: 0, warnCount: 0, successCount: 1},
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
    manifests:
      - name: simple-httpd-deployment
        namespace: httpd
        files:
          - httpd-deployment.yaml    	
    charts:
      - name: uds-app-config
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			want: wantResult{errorCount: 0, warnCount: 1, successCount: 0},
		},
	}

	for _, tt := range tests {
		tmpDir := t.TempDir()
		zarfYamlPath := filepath.Join(tmpDir, "zarf.yaml")

		if err := os.WriteFile(zarfYamlPath, []byte(tt.yaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}

		got := checkForManifests(zarfYamlPath)

		require.Equal(t, tt.want.errorCount, len(got.Errors))
		require.Equal(t, tt.want.warnCount, len(got.Warnings))
		require.Equal(t, tt.want.successCount, len(got.Successes))
	}
}

func TestGetNamespaces(t *testing.T) {
	tests := []struct {
		commonZarfYaml string
		rootZarfYaml   string
		want           []string
	}{
		{
			commonZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace1
      - name: app
        namespace: mynamespace2
`,
			rootZarfYaml: `
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
      - name: app
        namespace: mynamespace4
`,
			want: []string{"mynamespace1", "mynamespace2", "mynamespace3", "mynamespace4"},
		},
		{
			commonZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
    charts:
      - name: uds-app-config
        namespace: mynamespace1
      - name: app
        namespace: mynamespace2
`,
			rootZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"

components:
  - name: my-component
    required: true
`,
			want: []string{"mynamespace1", "mynamespace2"},
		},
		{
			commonZarfYaml: `
kind: ZarfPackageConfig
metadata:
  name: my-zarf-package
  description: "My UDS Package"
`,
			rootZarfYaml: `
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
      - name: app
        namespace: mynamespace4
`,
			want: []string{"mynamespace2", "mynamespace3", "mynamespace4"},
		},
	}

	for _, tt := range tests {
		tmpDir := t.TempDir()
		commonZarfYamlPath := filepath.Join(tmpDir, "common-zarf.yaml")
		rootZarfYamlPath := filepath.Join(tmpDir, "zarf.yaml")

		if err := os.WriteFile(commonZarfYamlPath, []byte(tt.commonZarfYaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}
		if err := os.WriteFile(rootZarfYamlPath, []byte(tt.rootZarfYaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}

		got, err := getNamespaces(commonZarfYamlPath, rootZarfYamlPath)

		require.Equal(t, err, nil)
		require.Equal(t, got, tt.want)
	}
}

func TestCheckForFlavors(t *testing.T) {
	type wantResult struct {
		errorCount   int
		warnCount    int
		successCount int
	}
	tests := []struct {
		yaml string
		want wantResult
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
    only:
      flavor: registry1	
    charts:
      - name: uds-app-config
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			want: wantResult{errorCount: 0, warnCount: 0, successCount: 1},
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
        namespace: mynamespace
      - name: app
        namespace: mynamespace
`,
			want: wantResult{errorCount: 1, warnCount: 0, successCount: 0},
		},
	}

	for _, tt := range tests {
		tmpDir := t.TempDir()
		zarfYamlPath := filepath.Join(tmpDir, "zarf.yaml")

		if err := os.WriteFile(zarfYamlPath, []byte(tt.yaml), 0644); err != nil {
			t.Fatalf("failed to write test YAML file: %v", err)
		}

		got := checkForFlavors(zarfYamlPath)

		require.Equal(t, tt.want.errorCount, len(got.Errors))
		require.Equal(t, tt.want.warnCount, len(got.Warnings))
		require.Equal(t, tt.want.successCount, len(got.Successes))
	}
}
