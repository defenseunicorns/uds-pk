// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func TestStandaloneComponentUpdateCommand(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		t.Run(fmt.Sprintf("scoped=%t", scoped), func(t *testing.T) {
			dir := t.TempDir()
			componentDir := dir
			config := "flavors:\n  - name: upstream\n    version: 2.0.0\n    source: upstream.yaml\n"
			args := []string{"release", "update-yaml", "upstream"}
			if scoped {
				componentDir = filepath.Join(dir, "components", "app")
				require.NoError(t, os.MkdirAll(componentDir, 0o755))
				config = "packages:\n  - name: app\n    path: components/app\n    flavors:\n      - name: upstream\n        version: 2.0.0\n        source: upstream.yaml\n"
				args = append(args, "--package", "app")
			}
			source := `# component source
apiVersion: zarf.dev/v1beta1
kind: ZarfComponentConfig
metadata:
  name: actual-component
  version: old # keep note
variant: {flavor: upstream, architecture: arm64}
component:
  import: {local: [{path: common.yaml}]}
  images: [{name: example.com/app:v1, id: app}]
`
			file := filepath.Join(componentDir, "upstream.yaml")
			require.NoError(t, os.WriteFile(file, []byte(source), 0o640))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "releaser.yaml"), []byte(config), 0o644))
			stdout, stderr, err := e2e.UDSPKDir(dir, args...)
			require.NoError(t, err, stdout, stderr)
			data, err := os.ReadFile(file)
			require.NoError(t, err)
			require.Equal(t, strings.Replace(source, "version: old", "version: 2.0.0", 1), string(data))
			showArgs := []string{"release", "show", "upstream"}
			wantTag := "2.0.0-upstream\n"
			if scoped {
				showArgs = append(showArgs, "--package", "app")
			}
			stdout, stderr, err = e2e.UDSPKDir(dir, showArgs...)
			require.NoError(t, err, stdout, stderr)
			require.Equal(t, wantTag, stdout)
		})
	}
}

func TestStandaloneComponentPublishCheck(t *testing.T) {
	for _, test := range []struct {
		name, flavor, architecture, manifest, child, want string
	}{
		{"generic", "", "", `{"config":{"mediaType":"application/vnd.zarf.component.config.v1+json"}}`, "", "false\n"},
		{"arm64 variant", "upstream", "arm64", `{"manifests":[{"digest":"sha256:arm","platform":{"architecture":"arm64"}}]}`, `{"config":{"mediaType":"application/vnd.zarf.component.config.v1+json"}}`, "false\n"},
		{"wrong artifact", "upstream", "arm64", `{"manifests":[{"digest":"sha256:arm","platform":{"architecture":"arm64"}}]}`, `{"config":{"mediaType":"application/vnd.zarf.config.v1+json"}}`, "true\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			source := fmt.Sprintf("apiVersion: zarf.dev/v1beta1\nkind: ZarfComponentConfig\nmetadata: {name: actual-component, version: 2.0.0}\nvariant: {flavor: %q, architecture: %q}\ncomponent: {}\n", test.flavor, test.architecture)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "component.yaml"), []byte(source), 0o644))
			config := fmt.Sprintf("flavors:\n  - name: %q\n    version: 2.0.0\n    source: component.yaml\n", test.flavor)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "releaser.yaml"), []byte(config), 0o644))
			repo, err := git.PlainInit(dir, false)
			require.NoError(t, err)
			worktree, err := repo.Worktree()
			require.NoError(t, err)
			_, err = worktree.Add("component.yaml")
			require.NoError(t, err)
			commit, err := worktree.Commit("component fixture", &git.CommitOptions{Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Unix(1, 0)}})
			require.NoError(t, err)
			tag := "2.0.0"
			if test.flavor != "" {
				tag += "-" + test.flavor
			}
			_, err = repo.CreateTag(tag, commit, nil)
			require.NoError(t, err)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v2/components/actual-component/manifests/" + tag:
					_, _ = w.Write([]byte(test.manifest))
				case "/v2/components/actual-component/manifests/sha256:arm":
					_, _ = w.Write([]byte(test.child))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			args := []string{"release", "check", "--boolean", "--plain-http", "--base-repo", server.URL + "/components"}
			if test.flavor != "" {
				args = append(args, test.flavor)
			}
			stdout, stderr, err := e2e.UDSPKDir(dir, args...)
			require.NoError(t, err, stdout, stderr)
			require.Equal(t, test.want, stdout)
			if test.architecture != "" {
				args = append(args, "--arch", "amd64")
				stdout, stderr, err = e2e.UDSPKDir(dir, args...)
				require.Error(t, err, stdout, stderr)
				require.Contains(t, stderr, "does not match component variant architecture")
			}
		})
	}
}
