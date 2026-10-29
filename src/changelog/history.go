// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// RevisionRange selects an explicit baseline or the entire initial history.
// From is excluded, To is included, and an empty To means HEAD.
type RevisionRange struct {
	From    string
	To      string
	Initial bool
}

// History holds resolved revisions and commits in stable order.
// Commit objects retain access to their trees for subsequent path filtering.
type History struct {
	Root    string
	Origin  string
	From    *object.Commit
	To      *object.Commit
	Commits []*object.Commit
}

type commitSet map[plumbing.Hash]struct{}

func (set commitSet) contains(hash plumbing.Hash) bool {
	_, found := set[hash]
	return found
}

// ReadHistory reads local objects without changing refs, the index, or files.
// Repository discovery is anchored to directory rather than the process cwd.
func ReadHistory(ctx context.Context, directory string, revisions RevisionRange) (History, error) {
	if (revisions.From != "") == revisions.Initial {
		return History{}, fmt.Errorf("specify exactly one of --from or --initial")
	}
	if revisions.To == "" {
		revisions.To = "HEAD"
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return History{}, fmt.Errorf("resolve release directory: %w", err)
	}
	repository, err := git.PlainOpenWithOptions(directory, &git.PlainOpenOptions{
		DetectDotGit: true, EnableDotGitCommonDir: true,
	})
	if err != nil {
		return History{}, fmt.Errorf("open repository from %q: %w", directory, err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return History{}, fmt.Errorf("open repository worktree: %w", err)
	}
	endpoint, err := resolveCommit(repository, revisions.To)
	if err != nil {
		return History{}, err
	}
	history := History{Root: worktree.Filesystem.Root(), To: endpoint}
	if origin, err := repository.Remote("origin"); err == nil && len(origin.Config().URLs) > 0 {
		history.Origin = origin.Config().URLs[0]
	}
	if !revisions.Initial {
		history.From, err = resolveCommit(repository, revisions.From)
		if err != nil {
			return History{}, err
		}
	}

	shallow, err := repository.Storer.Shallow()
	if err != nil {
		return History{}, fmt.Errorf("read shallow boundaries: %w", err)
	}
	boundaries := make(commitSet, len(shallow))
	for _, hash := range shallow {
		boundaries[hash] = struct{}{}
	}
	var excluded commitSet
	if history.From != nil {
		excluded, err = reachableCommits(ctx, repository, history.From.Hash, nil, boundaries, nil)
		if err != nil {
			return History{}, fmt.Errorf("establish baseline ancestry for %q: %w", revisions.From, err)
		}
	}
	var included []*object.Commit
	_, err = reachableCommits(ctx, repository, endpoint.Hash, excluded, boundaries, func(commit *object.Commit) {
		included = append(included, commit)
	})
	if err != nil {
		return History{}, err
	}
	if history.From != nil && history.From.Hash != endpoint.Hash {
		// The traversal stops at excluded commits, so the baseline is reachable
		// only when it is the endpoint or a parent of an included commit.
		ancestor := false
		for _, commit := range included {
			for _, parent := range commit.ParentHashes {
				if parent == history.From.Hash {
					ancestor = true
				}
			}
		}
		if !ancestor {
			return History{}, fmt.Errorf("baseline %q is not an ancestor of %q", revisions.From, revisions.To)
		}
	}
	history.Commits = included
	sort.Slice(history.Commits, func(left, right int) bool {
		leftCommit, rightCommit := history.Commits[left], history.Commits[right]
		if leftCommit.Committer.When.Equal(rightCommit.Committer.When) {
			return leftCommit.Hash.String() < rightCommit.Hash.String()
		}
		return leftCommit.Committer.When.Before(rightCommit.Committer.When)
	})
	return history, nil
}

func resolveCommit(repository *git.Repository, revision string) (*object.Commit, error) {
	hash, err := repository.ResolveRevision(plumbing.Revision(revision))
	if err != nil {
		return nil, fmt.Errorf("resolve revision %q: %w; fetch the required refs and history before generating notes", revision, err)
	}
	commit, err := repository.CommitObject(*hash)
	if err != nil {
		return nil, fmt.Errorf("read commit for revision %q: %w", revision, err)
	}
	return commit, nil
}

// reachableCommits requires complete ancestry for every visited commit. A
// shallow boundary cannot serve as a known root, including during baseline
// exclusion: ancestors hidden there may also be reached through another branch.
// Only hashes are retained; visit optionally collects objects for the result.
func reachableCommits(ctx context.Context, repository *git.Repository, start plumbing.Hash, excluded, boundaries commitSet, visit func(*object.Commit)) (commitSet, error) {
	seen := make(commitSet)
	pending := []plumbing.Hash{start}
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hash := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen.contains(hash) || excluded.contains(hash) {
			continue
		}
		if boundaries.contains(hash) {
			return nil, fmt.Errorf("history reaches shallow boundary %s; fetch complete history (git fetch --unshallow) before generating notes", hash)
		}
		commit, err := repository.CommitObject(hash)
		if err != nil {
			return nil, fmt.Errorf("read history commit %s: %w; fetch complete history before generating notes", hash, err)
		}
		seen[hash] = struct{}{}
		if visit != nil {
			visit(commit)
		}
		pending = append(pending, commit.ParentHashes...)
	}
	return seen, nil
}
