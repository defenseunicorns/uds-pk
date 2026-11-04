// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Artifact is a rendered file ready for writing.
type Artifact struct {
	Path    string
	Content []byte
}

type preparedArtifact struct {
	Artifact
	mode     fs.FileMode
	existing bool
}

// readArtifact reads an existing regular destination, following valid symlinks.
// A new destination returns no content. Validate the type before opening it so
// special files such as FIFOs cannot block changelog generation.
func readArtifact(path string) ([]byte, error) {
	destination, err := resolveDestination(path)
	if err != nil {
		return nil, err
	}
	if destination.existing == nil {
		return nil, nil
	}
	return os.ReadFile(destination.path)
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
			_ = os.RemoveAll(filepath.Dir(path))
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
	var destinations []artifactDestination
	for _, artifact := range artifacts {
		if artifact.Path == "" {
			return nil, fmt.Errorf("artifact path must not be empty")
		}
		destination, err := resolveDestination(artifact.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve artifact %q: %w", artifact.Path, err)
		}
		mode := fs.FileMode(0o644)
		if destination.existing != nil {
			mode = destination.existing.Mode().Perm()
		}
		destinations = append(destinations, destination)
		prepared = append(prepared, preparedArtifact{Artifact: Artifact{Path: destination.path, Content: artifact.Content}, mode: mode, existing: destination.existing != nil})
	}
	if err := validateDestinations(destinations); err != nil {
		return nil, err
	}
	return prepared, nil
}

func stageArtifact(artifact preparedArtifact) (path string, err error) {
	if err := os.MkdirAll(filepath.Dir(artifact.Path), 0o755); err != nil {
		return "", err
	}
	// A private staging directory lets normal file creation apply the caller's
	// umask to new artifacts while keeping unfinished content inaccessible.
	directory, err := os.MkdirTemp(filepath.Dir(artifact.Path), ".uds-pk-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(directory)
		}
	}()
	mode := artifact.mode
	if artifact.existing {
		mode = 0o600
	}
	path = filepath.Join(directory, "artifact")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	if _, err = file.Write(artifact.Content); err != nil {
		return path, err
	}
	if artifact.existing {
		if err = file.Chmod(artifact.mode); err != nil {
			return path, err
		}
	}
	if err = file.Sync(); err != nil {
		return path, err
	}
	err = file.Close()
	return path, err
}
