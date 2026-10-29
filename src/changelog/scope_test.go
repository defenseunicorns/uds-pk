// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func newScopeFixture(t *testing.T) historyFixture {
	t.Helper()
	var entries []struct {
		Name    string
		Message string
		Changes map[string]*string
	}
	require.NoError(t, utils.LoadYaml("testdata/scopes.yaml", &entries))
	directory, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	repository, err := git.PlainInit(directory, false)
	require.NoError(t, err)
	worktree, err := repository.Worktree()
	require.NoError(t, err)
	hashes := make(map[string]plumbing.Hash)
	for index, entry := range entries {
		var paths []string
		for path := range entry.Changes {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			content := entry.Changes[path]
			if content == nil {
				_, err := worktree.Remove(path)
				require.NoError(t, err)
				continue
			}
			absolute := filepath.Join(directory, filepath.FromSlash(path))
			require.NoError(t, os.MkdirAll(filepath.Dir(absolute), 0o755))
			require.NoError(t, os.WriteFile(absolute, []byte(*content), 0o644))
			_, err := worktree.Add(path)
			require.NoError(t, err)
		}
		hash, err := worktree.Commit(entry.Message, &git.CommitOptions{
			Author: &object.Signature{Name: "Fixture Author", Email: "fixture@example.test", When: time.Unix(int64(index+1), 0).UTC()},
		})
		require.NoError(t, err)
		hashes[entry.Name] = hash
	}
	return historyFixture{directory: directory, repository: repository, hashes: hashes}
}

func TestFilterCommits(t *testing.T) {
	fixture := newScopeFixture(t)
	history, err := readHistory(t.Context(), fixture.directory, RevisionRange{From: fixture.hashes["base"].String()})
	require.NoError(t, err)
	config, err := utils.LoadReleaseConfig("testdata")
	require.NoError(t, err)
	tests := []struct {
		name      string
		selection Selection
		include   []string
		want      []string
	}{
		{"root includes outside release directory", Selection{}, nil, []string{"api", "chart", "worker", "shared", "bundle", "rename-out", "rename-in", "deletion", "config", "outside"}},
		{"root include paths do not narrow scope", Selection{}, []string{"shared"}, []string{"api", "chart", "worker", "shared", "bundle", "rename-out", "rename-in", "deletion", "config", "outside"}},
		{"API and charts without worker prefix collision", Selection{Package: "api"}, nil, []string{"api", "chart", "rename-out", "rename-in", "deletion"}},
		{"flavor retains package path scope", Selection{Package: "api", Flavor: "upstream"}, nil, []string{"api", "chart", "rename-out", "rename-in", "deletion"}},
		{"explicit shared file", Selection{Package: "api"}, []string{"shared/runtime.go"}, []string{"api", "chart", "shared", "rename-out", "rename-in", "deletion"}},
		{"overlapping paths do not repeat commits", Selection{Package: "api"}, []string{"packages/api/", "./packages/api", "charts/api"}, []string{"api", "chart", "rename-out", "rename-in", "deletion"}},
		{"worker sees both sides of moves", Selection{Package: "api-worker"}, nil, []string{"worker", "rename-out", "rename-in"}},
		{"bundle does not inherit package history", Selection{Bundle: "platform"}, nil, []string{"bundle"}},
		{"bundle explicitly includes a package", Selection{Bundle: "platform"}, []string{"packages/api"}, []string{"api", "bundle", "rename-out", "rename-in", "deletion"}},
		{"unchanged bundle", Selection{Bundle: "platform-test"}, nil, nil},
		{"explicit repository scope", Selection{Package: "api"}, []string{".."}, []string{"api", "chart", "worker", "shared", "bundle", "rename-out", "rename-in", "deletion", "config", "outside"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := ResolveTarget(config, test.selection)
			require.NoError(t, err)
			commits, err := filterCommits(t.Context(), history, filepath.Join(fixture.directory, "project"), target, test.include)
			require.NoError(t, err)
			var want []string
			for _, name := range test.want {
				want = append(want, fixture.hashes[name].String())
			}
			require.Equal(t, want, commitHashes(commitHistory{Commits: commits}))
		})
	}
}

func TestFilterCommitsInitialAndDeletedPaths(t *testing.T) {
	fixture := newScopeFixture(t)
	history, err := readHistory(t.Context(), fixture.directory, RevisionRange{Initial: true})
	require.NoError(t, err)
	// Files that no longer exist in the worktree still select historical changes.
	target := Target{Paths: []string{"packages/api/remove.txt"}}
	commits, err := filterCommits(t.Context(), history, filepath.Join(fixture.directory, "project"), target, nil)
	require.NoError(t, err)
	require.Equal(t, []string{fixture.hashes["base"].String(), fixture.hashes["deletion"].String()}, commitHashes(commitHistory{Commits: commits}))

	// Nonexistent paths select no changes rather than requiring live files.
	commits, err = filterCommits(t.Context(), history, filepath.Join(fixture.directory, "project"), Target{Paths: []string{"future"}}, nil)
	require.NoError(t, err)
	require.Empty(t, commits)
}

func TestFilterCommitsValidation(t *testing.T) {
	fixture := newScopeFixture(t)
	history, err := readHistory(t.Context(), fixture.directory, RevisionRange{Initial: true})
	require.NoError(t, err)
	directory := filepath.Join(fixture.directory, "project")
	tests := []struct {
		name    string
		target  Target
		include []string
		message string
	}{
		{"empty path", Target{Paths: []string{""}}, nil, "non-empty path"},
		{"absolute path", Target{Paths: []string{directory}}, nil, "relative to the release directory"},
		{"escape target", Target{Paths: []string{"../../outside"}}, nil, "outside repository"},
		{"escape include on root", Target{}, []string{"../../outside"}, "outside repository"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commits, err := filterCommits(t.Context(), history, directory, test.target, test.include)
			require.ErrorContains(t, err, test.message)
			require.Empty(t, commits)
		})
	}
	_, err = filterCommits(t.Context(), history, t.TempDir(), Target{}, nil)
	require.ErrorContains(t, err, "outside repository")
	_, err = filterCommits(t.Context(), history, filepath.Join(directory, "missing"), Target{}, nil)
	require.ErrorContains(t, err, "resolve release directory")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = filterCommits(ctx, history, directory, Target{}, nil)
	require.ErrorIs(t, err, context.Canceled)
}

func TestFilterCommitsRelativeAndSymlinkDirectories(t *testing.T) {
	fixture := newScopeFixture(t)
	history, err := readHistory(t.Context(), fixture.directory, RevisionRange{Initial: true})
	require.NoError(t, err)
	cwd, err := os.Getwd()
	require.NoError(t, err)
	relative, err := filepath.Rel(cwd, filepath.Join(fixture.directory, "project"))
	require.NoError(t, err)
	link := filepath.Join(t.TempDir(), "project")
	require.NoError(t, os.Symlink(filepath.Join(fixture.directory, "project"), link))
	for _, directory := range []string{relative, link} {
		commits, err := filterCommits(t.Context(), history, directory, Target{Paths: []string{"packages/api/remove.txt"}}, nil)
		require.NoError(t, err)
		require.Equal(t, []string{fixture.hashes["base"].String(), fixture.hashes["deletion"].String()}, commitHashes(commitHistory{Commits: commits}))
	}
}

func TestFilterCommitsMissingTree(t *testing.T) {
	fixture := newScopeFixture(t)
	history, err := readHistory(t.Context(), fixture.directory, RevisionRange{Initial: true, To: fixture.hashes["base"].String()})
	require.NoError(t, err)
	treeHash := history.Commits[0].TreeHash.String()
	require.NoError(t, os.Remove(filepath.Join(fixture.directory, ".git", "objects", treeHash[:2], treeHash[2:])))
	_, err = filterCommits(t.Context(), history, filepath.Join(fixture.directory, "project"), Target{Paths: []string{"packages/api"}}, nil)
	require.ErrorContains(t, err, "inspect paths in commit "+fixture.hashes["base"].String())
}
