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

type historyFixture struct {
	directory  string
	repository *git.Repository
	hashes     map[string]plumbing.Hash
}

// Build a local repository from a declarative graph so history tests need no
// network, Git executable, global Git configuration, or process cwd changes.
func newHistoryFixture(t *testing.T) historyFixture {
	t.Helper()
	var fixture struct {
		Commits []struct {
			Name      string
			Message   string
			Parents   []string
			Timestamp int64
		}
	}
	require.NoError(t, utils.LoadYaml("testdata/history.yaml", &fixture))
	directory := t.TempDir()
	directory, err := filepath.EvalSymlinks(directory)
	require.NoError(t, err)
	repository, err := git.PlainInit(directory, false)
	require.NoError(t, err)
	treeObject := repository.Storer.NewEncodedObject()
	require.NoError(t, (&object.Tree{}).Encode(treeObject))
	treeHash, err := repository.Storer.SetEncodedObject(treeObject)
	require.NoError(t, err)
	hashes := make(map[string]plumbing.Hash)
	for _, entry := range fixture.Commits {
		signature := object.Signature{Name: "Fixture Author", Email: "fixture@example.test", When: time.Unix(entry.Timestamp, 0).UTC()}
		commit := &object.Commit{Author: signature, Committer: signature, Message: entry.Message, TreeHash: treeHash}
		for _, parent := range entry.Parents {
			hash, exists := hashes[parent]
			require.True(t, exists, "unknown parent %s", parent)
			commit.ParentHashes = append(commit.ParentHashes, hash)
		}
		encoded := repository.Storer.NewEncodedObject()
		require.NoError(t, commit.Encode(encoded))
		hash, err := repository.Storer.SetEncodedObject(encoded)
		require.NoError(t, err)
		hashes[entry.Name] = hash
		require.NoError(t, repository.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(entry.Name), hash)))
	}
	require.NoError(t, repository.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName("endpoint"))))
	_, err = repository.CreateTag("api-1.0.0-upstream", hashes["base"], nil)
	require.NoError(t, err)
	_, err = repository.CreateTag("api-annotated", hashes["base"], &git.CreateTagOptions{
		Tagger:  &object.Signature{Name: "Fixture Author", Email: "fixture@example.test", When: time.Unix(2, 0).UTC()},
		Message: "Previous API release",
	})
	require.NoError(t, err)
	// A different target's newer tag must not influence explicit range selection.
	_, err = repository.CreateTag("worker-9.0.0", hashes["endpoint"], nil)
	require.NoError(t, err)
	return historyFixture{directory: directory, repository: repository, hashes: hashes}
}

func TestReadHistoryRange(t *testing.T) {
	fixture := newHistoryFixture(t)
	// Discover the repository from a nested release directory, independently of cwd.
	directory := filepath.Join(fixture.directory, "projects", "api")
	require.NoError(t, os.MkdirAll(directory, 0o755))
	beforeHead, err := fixture.repository.Head()
	require.NoError(t, err)
	beforeHeadFile, err := os.ReadFile(filepath.Join(fixture.directory, ".git", "HEAD"))
	require.NoError(t, err)

	for _, baseline := range []string{"base", "api-1.0.0-upstream", "api-annotated", fixture.hashes["base"].String()} {
		t.Run(baseline, func(t *testing.T) {
			history, err := ReadHistory(context.Background(), directory, RevisionRange{From: baseline})
			require.NoError(t, err)
			require.Equal(t, fixture.directory, history.Root)
			require.Equal(t, fixture.hashes["base"], history.From.Hash)
			require.Equal(t, fixture.hashes["endpoint"], history.To.Hash)
			// Reach both branches, omit the merge wrapper, and order timestamp ties by hash.
			branches := []string{fixture.hashes["feature"].String(), fixture.hashes["maintenance"].String()}
			sort.Strings(branches)
			require.Equal(t, append(branches, fixture.hashes["endpoint"].String()), commitHashes(history))
		})
	}
	afterHead, err := fixture.repository.Head()
	require.NoError(t, err)
	require.Equal(t, beforeHead, afterHead)
	afterHeadFile, err := os.ReadFile(filepath.Join(fixture.directory, ".git", "HEAD"))
	require.NoError(t, err)
	require.Equal(t, beforeHeadFile, afterHeadFile)
	status, err := fixture.repository.Worktree()
	require.NoError(t, err)
	changes, err := status.Status()
	require.NoError(t, err)
	require.True(t, changes.IsClean())
}

func TestReadHistoryInitialAndEndpoints(t *testing.T) {
	fixture := newHistoryFixture(t)
	history, err := ReadHistory(context.Background(), fixture.directory, RevisionRange{Initial: true, To: "feature"})
	require.NoError(t, err)
	require.Nil(t, history.From)
	require.Equal(t, []string{fixture.hashes["root"].String(), fixture.hashes["base"].String(), fixture.hashes["feature"].String()}, commitHashes(history))

	history, err = ReadHistory(context.Background(), fixture.directory, RevisionRange{From: "api-annotated", To: "base"})
	require.NoError(t, err)
	require.Empty(t, history.Commits)
	require.Equal(t, history.From.Hash, history.To.Hash)
}

func TestReadHistoryErrors(t *testing.T) {
	fixture := newHistoryFixture(t)
	tests := []struct {
		name      string
		revisions RevisionRange
		message   string
	}{
		{"no baseline", RevisionRange{}, "exactly one"},
		{"both baseline modes", RevisionRange{From: "base", Initial: true}, "exactly one"},
		{"missing baseline", RevisionRange{From: "missing"}, "resolve revision \"missing\""},
		{"missing endpoint", RevisionRange{From: "base", To: "missing"}, "resolve revision \"missing\""},
		{"unrelated baseline", RevisionRange{From: "unrelated"}, "not an ancestor"},
		{"baseline is later", RevisionRange{From: "endpoint", To: "base"}, "not an ancestor"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			history, err := ReadHistory(context.Background(), fixture.directory, test.revisions)
			require.ErrorContains(t, err, test.message)
			require.Empty(t, history)
		})
	}
	_, err := ReadHistory(context.Background(), t.TempDir(), RevisionRange{Initial: true})
	require.ErrorContains(t, err, "open repository")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ReadHistory(ctx, fixture.directory, RevisionRange{Initial: true})
	require.ErrorIs(t, err, context.Canceled)
}

func TestReadHistoryShallowBoundaries(t *testing.T) {
	fixture := newHistoryFixture(t)
	require.NoError(t, fixture.repository.Storer.SetShallow([]plumbing.Hash{fixture.hashes["base"]}))
	_, err := ReadHistory(context.Background(), fixture.directory, RevisionRange{Initial: true})
	require.ErrorContains(t, err, "git fetch --unshallow")

	// A shallow boundary already excluded by the baseline does not truncate the range.
	history, err := ReadHistory(context.Background(), fixture.directory, RevisionRange{From: "base"})
	require.NoError(t, err)
	require.Len(t, history.Commits, 3)
	_, err = ReadHistory(context.Background(), fixture.directory, RevisionRange{From: "root"})
	require.ErrorContains(t, err, "git fetch --unshallow")
}

func TestReadHistoryMissingObject(t *testing.T) {
	fixture := newHistoryFixture(t)
	missing := filepath.Join(fixture.directory, ".git", "objects", fixture.hashes["feature"].String()[:2], fixture.hashes["feature"].String()[2:])
	require.NoError(t, os.Remove(missing))
	_, err := ReadHistory(context.Background(), fixture.directory, RevisionRange{From: "base"})
	require.ErrorContains(t, err, "fetch complete history")
}

func commitHashes(history History) []string {
	var hashes []string
	for _, commit := range history.Commits {
		hashes = append(hashes, commit.Hash.String())
	}
	return hashes
}
