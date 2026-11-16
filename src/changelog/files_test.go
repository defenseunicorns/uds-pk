// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/test"
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
	test.RequireFileContents(t, map[string]string{notes: "release notes", history: "updated history"})
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
			test.RequireFileContents(t, map[string]string{existing: "original"})
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
	test.RequireFileContents(t, map[string]string{target: "updated"})
	err = WriteArtifacts(Artifact{Path: link, Content: []byte("first")}, Artifact{Path: target, Content: []byte("second")})
	require.ErrorContains(t, err, "same file")
	test.RequireFileContents(t, map[string]string{target: "updated"})

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
	test.RequireFileContents(t, map[string]string{existing: "original"})
	matches, err := filepath.Glob(filepath.Join(directory, ".uds-pk-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestWriteArtifactsExistingFileAliases(t *testing.T) {
	for _, alias := range []string{"hard link", "case alias"} {
		t.Run(alias, func(t *testing.T) {
			directory := t.TempDir()
			original := filepath.Join(directory, "notes.md")
			alternate := filepath.Join(directory, "NOTES.md")
			require.NoError(t, os.WriteFile(original, []byte("original"), 0o644))
			if alias == "hard link" {
				alternate = filepath.Join(directory, "linked.md")
				require.NoError(t, os.Link(original, alternate))
			} else if _, err := os.Stat(alternate); errors.Is(err, os.ErrNotExist) {
				t.Skip("filesystem treats case variants as distinct filenames")
			} else {
				require.NoError(t, err)
			}
			err := WriteArtifacts(Artifact{Path: original, Content: []byte("notes")}, Artifact{Path: alternate, Content: []byte("changelog")})
			require.ErrorContains(t, err, "same file")
			test.RequireFileContents(t, map[string]string{original: "original", alternate: "original"})
		})
	}
}

func TestWriteArtifactsNewFileAliases(t *testing.T) {
	for _, filenames := range [][2]string{
		{"notes.md", "NOTES.md"},
		{"new/notes.md", "NEW/NOTES.md"},
		{"new/notes.md", "NEW/notes.md"},
		{"caf\u00e9.md", "cafe\u0301.md"},
		{"new/caf\u00e9.md", "NEW/cafe\u0301.md"},
		{"notes,api.md", "NOTES,API.md"},
	} {
		t.Run(filenames[0]+" and "+filenames[1], func(t *testing.T) {
			directory := t.TempDir()
			// Probe the actual filesystem semantics in a disposable sibling tree.
			probe := filepath.Join(directory, "probe", filenames[0])
			require.NoError(t, os.MkdirAll(filepath.Dir(probe), 0o755))
			require.NoError(t, os.WriteFile(probe, []byte("probe"), 0o644))
			_, probeErr := os.Stat(filepath.Join(directory, "probe", filenames[1]))
			aliases := probeErr == nil
			if !aliases {
				require.ErrorIs(t, probeErr, os.ErrNotExist)
			}
			first := filepath.Join(directory, "output", filenames[0])
			second := filepath.Join(directory, "output", filenames[1])
			err := WriteArtifacts(Artifact{Path: first, Content: []byte("notes")}, Artifact{Path: second, Content: []byte("changelog")})
			if aliases {
				require.ErrorContains(t, err, "same file")
				_, err = os.Stat(first)
				require.ErrorIs(t, err, os.ErrNotExist)
				_, err = os.Stat(second)
				require.ErrorIs(t, err, os.ErrNotExist)
				_, err = os.Stat(filepath.Join(directory, "output"))
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.NoError(t, err)
				test.RequireFileContents(t, map[string]string{first: "notes", second: "changelog"})
			}
			matches, err := filepath.Glob(filepath.Join(directory, ".uds-pk-*"))
			require.NoError(t, err)
			require.Empty(t, matches)
		})
	}
}

func TestWriteArtifactsAliasedParentPaths(t *testing.T) {
	directory := t.TempDir()
	probe := filepath.Join(directory, "case-probe")
	require.NoError(t, os.WriteFile(probe, nil, 0o600))
	if _, err := os.Stat(filepath.Join(directory, "CASE-PROBE")); errors.Is(err, os.ErrNotExist) {
		t.Skip("filesystem treats case variants as distinct paths")
	} else {
		require.NoError(t, err)
	}
	for _, paths := range [][2]string{{"new/notes.md", "NEW/NOTES.MD/child.md"}, {"new/NOTES.MD/child.md", "NEW/notes.md"}} {
		err := WriteArtifacts(Artifact{Path: filepath.Join(directory, paths[0])}, Artifact{Path: filepath.Join(directory, paths[1])})
		require.Error(t, err)
		_, err = os.Stat(filepath.Join(directory, "new"))
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}
