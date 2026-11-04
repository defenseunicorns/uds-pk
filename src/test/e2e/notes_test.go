// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/test"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/require"
)

func runNotesBinary(t *testing.T, directory string, args ...string) (string, string, error) {
	t.Helper()
	e2e.CommandLog = append(e2e.CommandLog, strings.Join(args, " "))
	cmd := exec.CommandContext(t.Context(), e2e.UDSPKBinPath, args...)
	cmd.Dir = directory
	cmd.Env = append(os.Environ(), "GITHUB_TOKEN=", "GITLAB_RELEASE_TOKEN=", "CI_PROJECT_ID=")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func notesRefs(t *testing.T, fixture test.NotesFixture) map[string]string {
	t.Helper()
	iterator, err := fixture.Repository.References()
	require.NoError(t, err)
	defer iterator.Close()
	refs := make(map[string]string)
	require.NoError(t, iterator.ForEach(func(ref *plumbing.Reference) error {
		refs[ref.Name().String()] = ref.String()
		return nil
	}))
	return refs
}

func TestNotesCLIWiringAndReadOnlyHistory(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	outside := t.TempDir()
	link := filepath.Join(t.TempDir(), "release")
	require.NoError(t, os.Symlink(fixture.Directory, link))
	relativeDirectory, err := filepath.Rel(outside, link)
	require.NoError(t, err)
	refs := notesRefs(t, fixture)
	configPath := filepath.Join(fixture.Directory, "releaser.yaml")
	configBefore := test.ReadFile(t, configPath)
	tests := []struct {
		args []string
		tag  string
	}{
		{[]string{"release", "notes", "upstream", "--verbose"}, "2.0.0-upstream"},
		{[]string{"release", "bundle", "notes", "platform"}, "platform-4.0.0"},
	}
	for _, current := range tests {
		args := append(append([]string(nil), current.args...), "-d", relativeDirectory, "--from", "previous-api")
		stdout, stderr, err := runNotesBinary(t, outside, args...)
		require.NoError(t, err, stderr)
		require.Empty(t, stderr)
		require.True(t, strings.HasPrefix(stdout, "# Release notes\n\n"), stdout)
		require.Contains(t, stdout, "## "+current.tag+"\n")
		require.NotContains(t, stdout, "Warning:")
		require.NotContains(t, stdout, "fixture-token")
	}
	require.Equal(t, refs, notesRefs(t, fixture))
	require.Equal(t, configBefore, test.ReadFile(t, configPath))
	worktree, err := fixture.Repository.Worktree()
	require.NoError(t, err)
	status, err := worktree.Status()
	require.NoError(t, err)
	require.True(t, status.IsClean())

	// Existing release commands retain the publishing warning.
	stdout, stderr, err := runNotesBinary(t, outside, "release", "show", "upstream", "--dir", fixture.Directory)
	require.NoError(t, err, stderr)
	require.Equal(t, "Warning: publishBundle is not implemented yet.\n2.0.0-upstream\n", stdout)
}

func TestNotesCLIArtifacts(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	outside := t.TempDir()
	args := []string{"release", "notes", "--package", "api", "--dir", fixture.Directory, "--from", "previous-api", "--include-path", "shared", "--output", "notes/api.md", "--changelog", "CHANGELOG.md"}
	stdout, stderr, err := runNotesBinary(t, outside, args...)
	require.NoError(t, err, stderr)
	require.Empty(t, stdout)
	require.Empty(t, stderr)
	notes := test.ReadFile(t, filepath.Join(fixture.Directory, "notes", "api.md"))
	require.True(t, strings.HasPrefix(string(notes), "# Release notes\n"))
	historyPath := filepath.Join(fixture.Directory, "CHANGELOG.md")
	history := test.ReadFile(t, historyPath)
	require.Contains(t, string(history), "<!-- uds-pk:release ")
	_, err = os.Stat(filepath.Join(outside, "notes"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestNotesCLIErrorsKeepStdoutAndFilesClean(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	outside := t.TempDir()
	for _, flags := range [][]string{
		{}, {"--from", "missing"},
	} {
		args := append([]string{"release", "notes", "--dir", fixture.Directory, "--output", "not-created/notes.md", "--changelog", "not-created/CHANGELOG.md"}, flags...)
		stdout, stderr, err := runNotesBinary(t, outside, args...)
		require.Error(t, err, args)
		require.Empty(t, stdout)
		require.NotEmpty(t, stderr)
		_, err = os.Stat(filepath.Join(fixture.Directory, "not-created"))
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}

func TestNotesCLIRejectsHandwrittenChangelogWithoutWriting(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	notesPath := filepath.Join(fixture.Directory, "notes.md")
	historyPath := filepath.Join(fixture.Directory, "CHANGELOG.md")
	history := []byte("# Changelog\n\n```text\nHandwritten example.\n")
	require.NoError(t, os.WriteFile(notesPath, []byte("original notes"), 0o644))
	require.NoError(t, os.WriteFile(historyPath, history, 0o644))
	stdout, stderr, err := runNotesBinary(t, t.TempDir(), "release", "notes", "--dir", fixture.Directory, "--initial", "--output", "notes.md", "--changelog", "CHANGELOG.md")
	require.Error(t, err)
	require.Empty(t, stdout)
	require.Contains(t, stderr, "use a new --changelog path")
	test.RequireFileContents(t, map[string]string{historyPath: string(history), notesPath: "original notes"})
}
