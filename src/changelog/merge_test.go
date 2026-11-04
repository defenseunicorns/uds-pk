// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func TestFilterMergeCommits(t *testing.T) {
	for _, test := range []struct {
		name, message           string
		left, right, result     map[string]string
		root, thirdParent, want bool
		dot, baselineLeft       bool
		include                 []string
	}{
		{name: "plain wrapper", message: "Merge branch", left: map[string]string{"api/file": "left"}, right: map[string]string{"worker/file": "right"}, result: map[string]string{"worker/file": "right"}},
		{name: "merge-only breaking change", message: "fix!: require authentication", result: map[string]string{"api/file": "authenticated"}, want: true},
		{name: "nonconventional resolution", message: "Resolve API conflict", left: map[string]string{"api/file": "left"}, right: map[string]string{"api/file": "right"}, result: map[string]string{"api/file": "resolved"}, want: true},
		{name: "conventional wrapper metadata", message: "feat: release API", right: map[string]string{"api/file": "right"}, result: map[string]string{"api/file": "right"}, want: true},
		{name: "breaking footer metadata", message: "Merge API\n\nBREAKING CHANGE: authentication required", right: map[string]string{"api/file": "right"}, result: map[string]string{"api/file": "right"}, want: true},
		{name: "stale side parent cannot re-release API", message: "fix!: require worker authentication", left: map[string]string{"api/file": "released"}, right: map[string]string{"worker/file": "worker"}, result: map[string]string{"worker/file": "worker"}, baselineLeft: true},
		{name: "metadata with no first-parent change", message: "feat: release API", left: map[string]string{"api/file": "left"}},
		{name: "dot scope retains metadata", message: "fix!: compatibility", dot: true, want: true},
		{name: "dot scope with duplicate", message: "fix!: compatibility", dot: true, include: []string{"."}, want: true},
		{name: "dot scope with shared path", message: "fix!: compatibility", dot: true, include: []string{"shared"}, want: true},
		{name: "dot scope with chart path", message: "fix!: compatibility", dot: true, include: []string{"charts/api"}, want: true},
		{name: "unrelated breaking merge", message: "fix!: require worker authentication", result: map[string]string{"worker/file": "authenticated"}},
		{name: "unrelated unique change", message: "Resolve worker", result: map[string]string{"worker/file": "resolved"}},
		{name: "root retains empty metadata", message: "fix!: remove compatibility", root: true, want: true},
		{name: "root drops empty wrapper", message: "Merge branch", root: true},
		{name: "root retains unique change", message: "Resolve worker", result: map[string]string{"worker/file": "resolved"}, root: true, want: true},
		{name: "octopus unique change", message: "Merge three branches", result: map[string]string{"api/file": "resolved"}, thirdParent: true, want: true},
		{name: "merge-only deletion", message: "Remove obsolete API", result: map[string]string{"api/file": ""}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			repository, err := git.PlainInit(directory, false)
			require.NoError(t, err)
			worktree, err := repository.Worktree()
			require.NoError(t, err)
			sequence := int64(0)
			commit := func(message string, parents []plumbing.Hash, files map[string]string) plumbing.Hash {
				t.Helper()
				if len(parents) > 0 {
					require.NoError(t, worktree.Reset(&git.ResetOptions{Commit: parents[0], Mode: git.HardReset}))
				}
				for path, content := range files {
					if content == "" {
						_, err = worktree.Remove(path)
						require.NoError(t, err)
						continue
					}
					absolute := filepath.Join(directory, path)
					require.NoError(t, os.MkdirAll(filepath.Dir(absolute), 0o755))
					require.NoError(t, os.WriteFile(absolute, []byte(content), 0o644))
					_, err = worktree.Add(path)
					require.NoError(t, err)
				}
				sequence++
				hash, err := worktree.Commit(message, &git.CommitOptions{Parents: parents, AllowEmptyCommits: true,
					Author: &object.Signature{Name: "Fixture Author", Email: "fixture@example.test", When: time.Unix(sequence, 0).UTC()},
				})
				require.NoError(t, err)
				return hash
			}
			base := commit("chore: baseline", nil, map[string]string{"api/file": "base", "worker/file": "base"})
			left := commit("Left branch", []plumbing.Hash{base}, test.left)
			right := commit("Right branch", []plumbing.Hash{base}, test.right)
			parents := []plumbing.Hash{left, right}
			if test.thirdParent {
				parents = append(parents, commit("Third branch", []plumbing.Hash{base}, nil))
			}
			merged := commit(test.message, parents, test.result)
			baseline := base
			if test.baselineLeft {
				baseline = left
			}
			history, err := readHistory(t.Context(), directory, RevisionRange{From: baseline.String()})
			require.NoError(t, err)
			require.Contains(t, commitHashes(history), merged.String())
			target := releaseTarget{Paths: []string{"api"}}
			if test.root {
				target.Paths = nil
			} else if test.dot {
				target.Paths = []string{"."}
			}
			selected, err := filterCommits(t.Context(), history, directory, target, test.include)
			require.NoError(t, err)
			hashes := commitHashes(commitHistory{Commits: selected})
			if test.want {
				require.Contains(t, hashes, merged.String())
			} else {
				require.NotContains(t, hashes, merged.String())
			}
			if test.baselineLeft {
				require.Empty(t, hashes)
			}
			if test.name == "merge-only breaking change" {
				require.Equal(t, []string{merged.String()}, hashes)
				sections := groupCommits(selected)
				require.Equal(t, breakingChanges, sections[0].Category)
				notes := renderNotes(releaseData{Target: releaseTarget{Tag: "2.0.0"}, Sections: sections}, "")
				require.Contains(t, string(notes), "require authentication")
				require.NotContains(t, string(notes), "No changes matched")
			}
		})
	}
}
