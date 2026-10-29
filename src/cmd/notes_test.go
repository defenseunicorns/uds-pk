// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/test"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func executeNotes(t *testing.T, factory func() *cobra.Command, args ...string) (string, string, error) {
	t.Helper()
	cmd := factory()
	cmd.SilenceErrors = true
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return stdout.String(), stderr.String(), err
}

func TestNotesSelectorFlags(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	tests := []struct {
		name    string
		factory func() *cobra.Command
		args    []string
		tag     string
	}{
		{"root default", notesCmd, nil, "root-flavorless"},
		{"package and flavor", notesCmd, []string{"upstream", "-p", "api"}, "api-2.0.0-upstream"},
		{"bundle argument", bundleNotesCmd, []string{"platform"}, "platform-4.0.0"},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			args := append(append([]string(nil), current.args...), "--dir", fixture.Directory, "--from", "previous-api")
			stdout, stderr, err := executeNotes(t, current.factory, args...)
			require.NoError(t, err)
			require.Empty(t, stderr)
			require.Contains(t, stdout, "## "+current.tag+"\n")
		})
	}
}

func TestNotesOutputAndIncludeFlags(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	args := []string{"--dir", fixture.Directory, "--package", "api", "--from", "previous-api", "--include-path", "shared/runtime.txt", "--include-path", "packages/worker", "--output", "notes/api.md", "--changelog", "packages/api/CHANGELOG.md"}
	stdout, stderr, err := executeNotes(t, notesCmd, args...)
	require.NoError(t, err)
	require.Empty(t, stdout)
	require.Empty(t, stderr)
	notesPath := filepath.Join(fixture.Directory, "notes", "api.md")
	historyPath := filepath.Join(fixture.Directory, "packages", "api", "CHANGELOG.md")
	notes := test.ReadFile(t, notesPath)
	history := test.ReadFile(t, historyPath)
	require.Contains(t, string(notes), "initialize the shared runtime")
	require.Contains(t, string(notes), "retry failed jobs")
	require.Contains(t, string(history), "## api-api-flavorless")

	// A changelog-only invocation still emits notes on stdout.
	stdout, _, err = executeNotes(t, notesCmd, "--dir", fixture.Directory, "--package", "api", "--from", "previous-api", "--include-path", "shared/runtime.txt", "--include-path", "packages/worker", "--changelog", historyPath)
	require.NoError(t, err)
	require.Equal(t, string(notes), stdout)
}

func TestNotesFailuresDoNotWrite(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	for _, args := range [][]string{
		{}, {"--initial", "--from", "previous-api"}, {"--from", ""}, {"--initial=false"},
		{"upstream", "extra", "--initial"},
		{"--initial", "--output", ""}, {"--initial", "--changelog", ""},
	} {
		args = append([]string{"--dir", fixture.Directory, "--output", "not-created/notes.md", "--changelog", "not-created/CHANGELOG.md"}, args...)
		stdout, _, err := executeNotes(t, notesCmd, args...)
		require.Error(t, err, args)
		require.Empty(t, stdout)
		_, err = os.Stat(filepath.Join(fixture.Directory, "not-created"))
		require.ErrorIs(t, err, os.ErrNotExist)
	}

	_, _, err := executeNotes(t, bundleNotesCmd, "--dir", fixture.Directory, "--initial")
	require.Error(t, err)
}

func TestNotesRevisionFlags(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	stdout, stderr, err := executeNotes(t, notesCmd, "--dir", fixture.Directory, "--initial", "--to", fixture.Base)
	require.NoError(t, err)
	require.Empty(t, stderr)
	require.Contains(t, stdout, "Initial release (all reachable history)")
	require.Contains(t, stdout, "**Revision:** ["+fixture.Base+"]")
}

func TestNotesOutputErrorsAndCancellation(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	cmd := notesCmd()
	cmd.SetOut(notesFailureWriter{})
	cmd.SetErr(io.Discard)
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--dir", fixture.Directory, "--initial"})
	require.ErrorContains(t, cmd.ExecuteContext(t.Context()), "write release notes to stdout")
	cmd = notesCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--dir", fixture.Directory, "--initial", "--output", "not-created/notes.md"})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, cmd.ExecuteContext(ctx), context.Canceled)
	_, err := os.Stat(filepath.Join(fixture.Directory, "not-created"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

type notesFailureWriter struct{}

func (notesFailureWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }
