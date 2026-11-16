// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type artifactDestination struct {
	path       string
	existing   fs.FileInfo
	parent     string
	parentInfo fs.FileInfo
	relative   string
}

// Resolve existing symlinks while allowing new directories and filenames.
// For new files, retain the nearest existing directory and the remaining path
// so aliases can be checked before creating any destination directories.
func resolveDestination(path string) (artifactDestination, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return artifactDestination{}, err
	}
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			info, err := os.Stat(resolved)
			if err != nil {
				return artifactDestination{}, err
			}
			if len(missing) == 0 {
				if !info.Mode().IsRegular() {
					return artifactDestination{}, fmt.Errorf("artifact destination %q is not a regular file", path)
				}
				return artifactDestination{path: resolved, existing: info}, nil
			}
			if !info.IsDir() {
				return artifactDestination{}, fmt.Errorf("parent path %q is not a directory", resolved)
			}
			slices.Reverse(missing)
			relative := filepath.Join(missing...)
			return artifactDestination{path: filepath.Join(resolved, relative), parent: resolved, parentInfo: info, relative: relative}, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return artifactDestination{}, err
		}
		if info, statErr := os.Lstat(current); statErr == nil && info.Mode()&fs.ModeSymlink != 0 {
			return artifactDestination{}, fmt.Errorf("symlink %q has a missing target", current)
		}
		missing = append(missing, filepath.Base(current))
		parent := filepath.Dir(current)
		if parent == current {
			return artifactDestination{}, err
		}
		current = parent
	}
}

func validateDestinations(destinations []artifactDestination) error {
	for index, destination := range destinations {
		for _, previous := range destinations[:index] {
			if destination.path == previous.path || (destination.existing != nil && previous.existing != nil && os.SameFile(destination.existing, previous.existing)) {
				return fmt.Errorf("artifact destinations refer to the same file: %q and %q", previous.path, destination.path)
			}
			if strings.HasPrefix(destination.path, previous.path+string(filepath.Separator)) || strings.HasPrefix(previous.path, destination.path+string(filepath.Separator)) {
				return fmt.Errorf("artifact destination %q is a parent of another destination", destination.path)
			}
		}
	}
	// Existing files have inode identities. New files do not, so group them by
	// their nearest existing directory's identity and check proposed names on
	// that filesystem. This handles both case folding and Unicode normalization
	// without assuming a case policy from the operating system alone.
	var groups [][]artifactDestination
	for _, destination := range destinations {
		if destination.existing != nil {
			continue
		}
		groupIndex := slices.IndexFunc(groups, func(group []artifactDestination) bool {
			return os.SameFile(group[0].parentInfo, destination.parentInfo)
		})
		if groupIndex < 0 {
			groups = append(groups, []artifactDestination{destination})
		} else {
			groups[groupIndex] = append(groups[groupIndex], destination)
		}
	}
	for _, group := range groups {
		if len(group) > 1 {
			if err := checkNewDestinations(group); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkNewDestinations(destinations []artifactDestination) error {
	// An isolated temporary tree mirrors only the proposed missing path suffixes.
	// No real output path or directory is created during this check. The tree
	// lives under their existing parent to inherit its filesystem name semantics.
	probe, err := os.MkdirTemp(destinations[0].parent, ".uds-pk-*")
	if err != nil {
		return fmt.Errorf("check artifact destinations: %w", err)
	}
	defer func() { _ = os.RemoveAll(probe) }()
	root, err := os.OpenRoot(probe)
	if err != nil {
		return fmt.Errorf("open artifact destination check: %w", err)
	}
	defer func() { _ = root.Close() }()
	for _, destination := range destinations {
		if err := root.MkdirAll(filepath.Dir(destination.relative), 0o700); err != nil {
			return fmt.Errorf("check artifact destination %q: %w", destination.path, err)
		}
		file, err := root.OpenFile(destination.relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("artifact destinations refer to the same file or a parent directory: %q", destination.path)
		}
		if err != nil {
			return fmt.Errorf("check artifact destination %q: %w", destination.path, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close artifact destination check: %w", err)
		}
	}
	return nil
}
