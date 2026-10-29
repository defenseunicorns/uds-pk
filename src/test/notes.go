// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"embed"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	goyaml "github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/notes/*.yaml
var notesFixtures embed.FS

// NotesFixture is a disposable, local Git repository shared by command and
// executable tests. Its release directory is nested below its repository root.
type NotesFixture struct {
	Repository *git.Repository
	Directory  string
	Base       string
	Head       string
}

// CreateNotesFixture materializes a deterministic release history without a
// network connection, Git executable, or changes to the process working directory.
func CreateNotesFixture(t *testing.T) NotesFixture {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "project")
	require.NoError(t, os.MkdirAll(directory, 0o755))
	repository, err := git.PlainInit(root, false)
	require.NoError(t, err)
	_, err = repository.CreateRemote(&config.RemoteConfig{
		Name: "origin", URLs: []string{"https://example-user:fixture-token@github.com/example/notes-fixture.git"},
	})
	require.NoError(t, err)
	worktree, err := repository.Worktree()
	require.NoError(t, err)
	releaseConfig, err := notesFixtures.ReadFile("fixtures/notes/releaser.yaml")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "releaser.yaml"), releaseConfig, 0o644))
	_, err = worktree.Add("project/releaser.yaml")
	require.NoError(t, err)
	var entries []struct {
		Message string
		Files   map[string]string
	}
	commits, err := notesFixtures.ReadFile("fixtures/notes/commits.yaml")
	require.NoError(t, err)
	require.NoError(t, goyaml.Unmarshal(commits, &entries))
	fixture := NotesFixture{Repository: repository, Directory: directory}
	for index, entry := range entries {
		var paths []string
		for path := range entry.Files {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			absolute := filepath.Join(directory, filepath.FromSlash(path))
			require.NoError(t, os.MkdirAll(filepath.Dir(absolute), 0o755))
			require.NoError(t, os.WriteFile(absolute, []byte(entry.Files[path]), 0o644))
			_, err := worktree.Add("project/" + path)
			require.NoError(t, err)
		}
		hash, err := worktree.Commit(entry.Message, &git.CommitOptions{
			Author: &object.Signature{Name: "Fixture Author", Email: "fixture@example.test", When: time.Date(2026, 10, 20+index, 12, 0, 0, 0, time.UTC)},
		})
		require.NoError(t, err)
		if index == 0 {
			fixture.Base = hash.String()
			_, err := repository.CreateTag("previous-api", hash, nil)
			require.NoError(t, err)
		}
		fixture.Head = hash.String()
	}
	return fixture
}
