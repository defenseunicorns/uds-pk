// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteArtifacts(t *testing.T) {
	directory := t.TempDir()
	notes := filepath.Join(directory, "notes", "release.md")
	history := filepath.Join(directory, "CHANGELOG.md")
	require.NoError(t, os.WriteFile(history, []byte("previous"), 0o640))
	require.NoError(t, os.Chmod(history, 0o640))
	require.NoError(t, WriteArtifacts(
		Artifact{Path: notes, Content: []byte("release notes")},
		Artifact{Path: history, Content: []byte("updated history")},
	))
	content, err := os.ReadFile(notes)
	require.NoError(t, err)
	require.Equal(t, "release notes", string(content))
	content, err = os.ReadFile(history)
	require.NoError(t, err)
	require.Equal(t, "updated history", string(content))
	info, err := os.Stat(history)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
	for _, parent := range []string{directory, filepath.Dir(notes)} {
		matches, err := filepath.Glob(filepath.Join(parent, ".uds-pk-*"))
		require.NoError(t, err)
		require.Empty(t, matches)
	}
	require.NoError(t, WriteArtifacts())
}

func TestWriteArtifactsValidatesBeforeWriting(t *testing.T) {
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing.md")
	require.NoError(t, os.WriteFile(existing, []byte("original"), 0o644))
	for name, path := range map[string]string{
		"empty": "", "directory": directory, "duplicate": existing,
		"file as parent": filepath.Join(existing, "notes.md"),
	} {
		t.Run(name, func(t *testing.T) {
			err := WriteArtifacts(Artifact{Path: existing, Content: []byte("replaced")}, Artifact{Path: path, Content: []byte("other")})
			require.Error(t, err)
			content, err := os.ReadFile(existing)
			require.NoError(t, err)
			require.Equal(t, "original", string(content))
		})
	}
	newPath := filepath.Join(directory, "not-created", "notes.md")
	require.Error(t, WriteArtifacts(Artifact{Path: newPath}, Artifact{Path: directory}))
	_, err := os.Stat(filepath.Dir(newPath))
	require.ErrorIs(t, err, os.ErrNotExist)
	err = WriteArtifacts(Artifact{Path: newPath}, Artifact{Path: filepath.Join(newPath, "child.md")})
	require.ErrorContains(t, err, "parent of another destination")
	_, err = os.Stat(filepath.Dir(newPath))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestWriteArtifactsSymlinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.md")
	link := filepath.Join(directory, "link.md")
	require.NoError(t, os.WriteFile(target, []byte("original"), 0o644))
	require.NoError(t, os.Symlink("target.md", link))
	require.NoError(t, WriteArtifacts(Artifact{Path: link, Content: []byte("updated")}))
	info, err := os.Lstat(link)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "updated", string(content))
	err = WriteArtifacts(Artifact{Path: link, Content: []byte("first")}, Artifact{Path: target, Content: []byte("second")})
	require.ErrorContains(t, err, "same file")
	content, err = os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "updated", string(content))

	parentLink := filepath.Join(directory, "parent-link")
	require.NoError(t, os.Symlink(directory, parentLink))
	err = WriteArtifacts(
		Artifact{Path: filepath.Join(parentLink, "new.md")},
		Artifact{Path: filepath.Join(directory, "new.md")},
	)
	require.ErrorContains(t, err, "same file")
	dangling := filepath.Join(directory, "dangling")
	require.NoError(t, os.Symlink("missing", dangling))
	err = WriteArtifacts(Artifact{Path: dangling, Content: []byte("replacement")})
	require.ErrorContains(t, err, "missing target")
	info, err = os.Lstat(dangling)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
}

func TestWriteArtifactsStagesAllBeforeReplacing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permission used to exercise a staging failure")
	}
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing.md")
	locked := filepath.Join(directory, "locked")
	require.NoError(t, os.WriteFile(existing, []byte("original"), 0o644))
	require.NoError(t, os.Mkdir(locked, 0o555))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	// Both destinations validate, but the second cannot be staged.
	err := WriteArtifacts(Artifact{Path: existing, Content: []byte("changed")}, Artifact{Path: filepath.Join(locked, "other.md")})
	require.ErrorContains(t, err, "stage artifact")
	content, err := os.ReadFile(existing)
	require.NoError(t, err)
	require.Equal(t, "original", string(content))
	matches, err := filepath.Glob(filepath.Join(directory, ".uds-pk-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}
