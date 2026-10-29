// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Artifact is a rendered file ready for writing.
type Artifact struct {
	Path    string
	Content []byte
}

type preparedArtifact struct {
	Artifact
	mode fs.FileMode
}

// WriteArtifacts validates every destination and stages every file before
// replacing destinations through atomic renames. It creates parent directories
// as needed and preserves existing file permissions and symlinks. Replacement
// of multiple files is not a cross-file transaction: a later rename can fail
// after an earlier rename succeeded.
func WriteArtifacts(artifacts ...Artifact) error {
	prepared, err := prepareArtifacts(artifacts)
	if err != nil {
		return err
	}
	var staged []string
	defer func() {
		for _, path := range staged {
			_ = os.Remove(path)
		}
	}()
	for _, artifact := range prepared {
		path, err := stageArtifact(artifact)
		if err != nil {
			return fmt.Errorf("stage artifact %q: %w", artifact.Path, err)
		}
		staged = append(staged, path)
	}
	for index, artifact := range prepared {
		if err := os.Rename(staged[index], artifact.Path); err != nil {
			return fmt.Errorf("replace artifact %q: %w", artifact.Path, err)
		}
	}
	return nil
}

func prepareArtifacts(artifacts []Artifact) ([]preparedArtifact, error) {
	var prepared []preparedArtifact
	seen := make(map[string]bool)
	for _, artifact := range artifacts {
		if artifact.Path == "" {
			return nil, fmt.Errorf("artifact path must not be empty")
		}
		path, err := resolveDestination(artifact.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve artifact %q: %w", artifact.Path, err)
		}
		if seen[path] {
			return nil, fmt.Errorf("artifact destinations refer to the same file: %q", artifact.Path)
		}
		for previous := range seen {
			if strings.HasPrefix(path, previous+string(filepath.Separator)) || strings.HasPrefix(previous, path+string(filepath.Separator)) {
				return nil, fmt.Errorf("artifact destination %q is a parent of another destination", artifact.Path)
			}
		}
		seen[path] = true
		mode := fs.FileMode(0o644)
		info, err := os.Stat(path)
		if err == nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("artifact destination %q is not a regular file", artifact.Path)
			}
			mode = info.Mode().Perm()
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("inspect artifact %q: %w", artifact.Path, err)
		}
		prepared = append(prepared, preparedArtifact{Artifact: Artifact{Path: path, Content: artifact.Content}, mode: mode})
	}
	return prepared, nil
}

// Resolve existing symlinks, including parent directories, while allowing new
// directories and filenames. A dangling symlink is an error, not a new output
// file whose creation would replace the symlink itself.
func resolveDestination(path string) (string, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			if len(missing) > 0 {
				info, err := os.Stat(resolved)
				if err != nil {
					return "", err
				}
				if !info.IsDir() {
					return "", fmt.Errorf("parent path %q is not a directory", resolved)
				}
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return resolved, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if info, statErr := os.Lstat(current); statErr == nil && info.Mode()&fs.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink %q has a missing target", current)
		}
		missing = append(missing, filepath.Base(current))
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		current = parent
	}
}

func stageArtifact(artifact preparedArtifact) (path string, err error) {
	if err := os.MkdirAll(filepath.Dir(artifact.Path), 0o755); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(filepath.Dir(artifact.Path), ".uds-pk-*")
	if err != nil {
		return "", err
	}
	path = file.Name()
	defer func() {
		_ = file.Close()
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(artifact.Content); err != nil {
		return path, err
	}
	if err = file.Chmod(artifact.mode); err != nil {
		return path, err
	}
	if err = file.Sync(); err != nil {
		return path, err
	}
	err = file.Close()
	return path, err
}
