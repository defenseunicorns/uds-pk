// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
)

// filterCommits selects commits touching the target's paths or explicit shared
// paths. Root targets cover the whole repository. Paths are relative to the
// release directory. Only selected commits are sorted, by commit time then hash.
func filterCommits(ctx context.Context, history commitHistory, directory string, target releaseTarget, includePaths []string) ([]*object.Commit, error) {
	paths := append(append([]string(nil), target.Paths...), includePaths...)
	scopes, err := resolveScopes(history.Root, directory, paths)
	if err != nil {
		return nil, err
	}
	// Validate every supplied path before reducing the union to repository scope.
	if len(target.Paths) == 0 {
		scopes = []string{"."}
	}
	repositoryWide := len(scopes) == 1 && scopes[0] == "."
	var selected []*object.Commit
	for _, commit := range history.Commits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hash := commit.Hash.String()
		if repositoryWide && commit.NumParents() <= 1 {
			selected = append(selected, commit)
			continue
		}
		matches, err := commitRelevant(ctx, commit, scopes, repositoryWide)
		if err != nil {
			return nil, fmt.Errorf("inspect paths in commit %s: %w", hash, err)
		}
		if matches {
			selected = append(selected, commit)
		}
	}
	sort.Slice(selected, func(left, right int) bool {
		leftCommit, rightCommit := selected[left], selected[right]
		if leftCommit.Committer.When.Equal(rightCommit.Committer.When) {
			return leftCommit.Hash.String() < rightCommit.Hash.String()
		}
		return leftCommit.Committer.When.Before(rightCommit.Committer.When)
	})
	return selected, nil
}

func resolveScopes(root, directory string, paths []string) ([]string, error) {
	root, err := canonicalDirectory(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository directory: %w", err)
	}
	directory, err = canonicalDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve release directory: %w", err)
	}
	if _, err := repositoryPath(root, directory); err != nil {
		return nil, err
	}
	var scopes []string
	for _, path := range paths {
		if path == "" || filepath.IsAbs(path) {
			return nil, fmt.Errorf("scope %q must be a non-empty path relative to the release directory", path)
		}
		scope, err := repositoryPath(root, filepath.Join(directory, path))
		if err != nil {
			return nil, fmt.Errorf("resolve scope %q: %w", path, err)
		}
		scopes = append(scopes, filepath.ToSlash(scope))
	}
	// A repository-wide member subsumes every other path. Resolve all paths
	// first so redundant include paths still receive validation.
	for _, scope := range scopes {
		if scope == "." {
			return []string{"."}, nil
		}
	}
	return scopes, nil
}

func canonicalDirectory(directory string) (string, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}

func repositoryPath(root, path string) (string, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q within repository: %w", path, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside repository %q", path, root)
	}
	return relative, nil
}

// Metadata describes the merge's change to its first-parent branch. Comparing
// it with a stale side parent would attribute already-released changes to this
// merge. Plain wrappers are retained only for final path states absent from all
// parents, so conflict resolutions and merge-only changes remain visible.
func commitRelevant(ctx context.Context, commit *object.Commit, scopes []string, repositoryWide bool) (bool, error) {
	if commit.NumParents() <= 1 {
		changed, err := changedPaths(ctx, commit, 0, scopes)
		return len(changed) > 0, err
	}
	message := parseMessage(commit.Message)
	metadata := message.Type != "" || len(message.BreakingDescriptions) > 0
	if metadata {
		if repositoryWide {
			return true, nil
		}
		changed, err := changedPaths(ctx, commit, 0, scopes)
		return len(changed) > 0, err
	}
	changedInParents := make(map[string]int)
	for index := 0; index < commit.NumParents(); index++ {
		changed, err := changedPaths(ctx, commit, index, scopes)
		if err != nil {
			return false, err
		}
		if len(changed) == 0 {
			return false, nil
		}
		for path := range changed {
			changedInParents[path]++
			if changedInParents[path] == commit.NumParents() {
				return true, nil
			}
		}
	}
	return false, nil
}

func changedPaths(ctx context.Context, commit *object.Commit, parentIndex int, scopes []string) (map[string]bool, error) {
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}
	var parentTree *object.Tree
	if commit.NumParents() > 0 {
		parent, err := commit.Parent(parentIndex)
		if err != nil {
			return nil, err
		}
		parentTree, err = parent.Tree()
		if err != nil {
			return nil, err
		}
	}
	// Without rename detection, both sides of a move participate in scope.
	changes, err := object.DiffTreeContext(ctx, parentTree, tree)
	if err != nil {
		return nil, err
	}
	changed := make(map[string]bool)
	for _, change := range changes {
		for _, path := range []string{change.From.Name, change.To.Name} {
			for _, scope := range scopes {
				if pathMatchesScope(path, scope) {
					changed[path] = true
				}
			}
		}
	}
	return changed, nil
}

func pathMatchesScope(path, scope string) bool {
	return path != "" && (scope == "." || path == scope || strings.HasPrefix(path, scope+"/"))
}
