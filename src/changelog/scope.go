// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
)

// FilterCommits selects commits touching the target's paths or explicit shared
// paths. Root targets cover the whole repository. Paths are relative to the
// release directory; returned commits retain the history's order.
func FilterCommits(ctx context.Context, history History, directory string, target Target, includePaths []string) ([]*object.Commit, error) {
	paths := append(append([]string(nil), target.Paths...), includePaths...)
	scopes, err := resolveScopes(history.Root, directory, paths)
	if err != nil {
		return nil, err
	}
	var selected []*object.Commit
	seen := make(map[string]bool)
	for _, commit := range history.Commits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hash := commit.Hash.String()
		if seen[hash] {
			continue
		}
		seen[hash] = true
		if len(target.Paths) == 0 {
			selected = append(selected, commit)
			continue
		}
		matches, err := commitTouchesPaths(ctx, commit, scopes)
		if err != nil {
			return nil, fmt.Errorf("inspect paths in commit %s: %w", hash, err)
		}
		if matches {
			selected = append(selected, commit)
		}
	}
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

func commitTouchesPaths(ctx context.Context, commit *object.Commit, scopes []string) (bool, error) {
	tree, err := commit.Tree()
	if err != nil {
		return false, err
	}
	var parentTree *object.Tree
	if commit.NumParents() > 0 {
		parent, err := commit.Parent(0)
		if err != nil {
			return false, err
		}
		parentTree, err = parent.Tree()
		if err != nil {
			return false, err
		}
	}
	// Rename detection is unnecessary for membership: the removed path and
	// added path are both considered, including moves across target boundaries.
	changes, err := object.DiffTreeContext(ctx, parentTree, tree)
	if err != nil {
		return false, err
	}
	for _, change := range changes {
		for _, scope := range scopes {
			if pathMatchesScope(change.From.Name, scope) || pathMatchesScope(change.To.Name, scope) {
				return true, nil
			}
		}
	}
	return false, nil
}

func pathMatchesScope(path, scope string) bool {
	return path != "" && (scope == "." || path == scope || strings.HasPrefix(path, scope+"/"))
}
