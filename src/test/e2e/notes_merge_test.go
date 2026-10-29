// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/test"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func TestNotesCLIMergeOnlyBreakingChange(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	base, err := fixture.Repository.CommitObject(plumbing.NewHash(fixture.Head))
	require.NoError(t, err)
	var parents []plumbing.Hash
	for _, message := range []string{"Left branch", "Right branch"} {
		parent := &object.Commit{Author: base.Author, Committer: base.Committer, TreeHash: base.TreeHash, ParentHashes: []plumbing.Hash{base.Hash}, Message: message}
		encoded := fixture.Repository.Storer.NewEncodedObject()
		require.NoError(t, parent.Encode(encoded))
		hash, err := fixture.Repository.Storer.SetEncodedObject(encoded)
		require.NoError(t, err)
		parents = append(parents, hash)
	}
	require.NoError(t, os.WriteFile(filepath.Join(fixture.Directory, "packages/api/authentication.txt"), []byte("Authentication required"), 0o644))
	worktree, err := fixture.Repository.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("project/packages/api/authentication.txt")
	require.NoError(t, err)
	merged, err := worktree.Commit("fix!: require authentication", &git.CommitOptions{Parents: parents, Author: &base.Author})
	require.NoError(t, err)
	refs := notesRefs(t, fixture)
	stdout, stderr, err := runNotesBinary(t, t.TempDir(), "release", "notes", "upstream", "--package", "api", "--dir", fixture.Directory, "--from", fixture.Head)
	require.NoError(t, err, stderr)
	require.Empty(t, stderr)
	require.Contains(t, stdout, "### Breaking Changes")
	require.Contains(t, stdout, "require authentication")
	require.Contains(t, stdout, merged.String())
	require.NotContains(t, stdout, "No changes matched")
	require.Equal(t, refs, notesRefs(t, fixture))
}
