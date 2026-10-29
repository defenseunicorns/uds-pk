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
	"github.com/defenseunicorns/uds-pk/src/types"
	goyaml "github.com/goccy/go-yaml"
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

func TestNotesTargetSelectors(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	tests := []struct {
		name    string
		factory func() *cobra.Command
		args    []string
		tag     string
		include string
		exclude string
	}{
		{"root flavored", notesCmd, []string{"upstream"}, "2.0.0-upstream", "retry failed jobs", ""},
		{"root flavorless", notesCmd, nil, "root-flavorless", "retry failed jobs", ""},
		{"package flavored", notesCmd, []string{"upstream", "--package", "api"}, "api-2.0.0-upstream", "configure API replicas", "retry failed jobs"},
		{"package flavorless", notesCmd, []string{"--package", "api"}, "api-api-flavorless", "reject malformed requests", "initialize the shared runtime"},
		{"second package", notesCmd, []string{"--package", "worker"}, "worker-3.0.0", "retry failed jobs", "expose the health endpoint"},
		{"bundle", bundleNotesCmd, []string{"platform"}, "platform-4.0.0", "refresh platform references", "expose the health endpoint"},
		{"second bundle", bundleNotesCmd, []string{"platform-test"}, "platform-test-testing", "No changes matched", "expose the health endpoint"},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			args := append(append([]string(nil), current.args...), "--dir", fixture.Directory, "--from", "previous-api")
			stdout, stderr, err := executeNotes(t, current.factory, args...)
			require.NoError(t, err)
			require.Empty(t, stderr)
			require.Contains(t, stdout, "## "+current.tag+"\n")
			require.Contains(t, stdout, current.include)
			if current.exclude != "" {
				require.NotContains(t, stdout, current.exclude)
			}
			require.NotContains(t, stdout, "fixture-token")
			require.Contains(t, stdout, "/compare/"+fixture.Base+"..."+fixture.Head)
		})
	}
}

func TestNotesArtifactsAndRepeatRuns(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	args := []string{"--dir", fixture.Directory, "--package", "api", "--from", "previous-api", "--include-path", "shared/runtime.txt", "--output", "notes/api.md", "--changelog", "packages/api/CHANGELOG.md"}
	stdout, stderr, err := executeNotes(t, notesCmd, args...)
	require.NoError(t, err)
	require.Empty(t, stdout)
	require.Empty(t, stderr)
	notesPath := filepath.Join(fixture.Directory, "notes", "api.md")
	historyPath := filepath.Join(fixture.Directory, "packages", "api", "CHANGELOG.md")
	notes, err := os.ReadFile(notesPath)
	require.NoError(t, err)
	history, err := os.ReadFile(historyPath)
	require.NoError(t, err)
	require.Contains(t, string(notes), "initialize the shared runtime")
	require.NotContains(t, string(notes), "retry failed jobs")
	require.Contains(t, string(history), "## api-api-flavorless")
	_, _, err = executeNotes(t, notesCmd, args...)
	require.NoError(t, err)
	repeated, err := os.ReadFile(historyPath)
	require.NoError(t, err)
	require.Equal(t, history, repeated)

	// A changelog-only invocation still emits notes on stdout.
	stdout, _, err = executeNotes(t, notesCmd, "--dir", fixture.Directory, "--package", "api", "--from", "previous-api", "--include-path", "shared/runtime.txt", "--changelog", historyPath)
	require.NoError(t, err)
	require.Equal(t, string(notes), stdout)
}

func TestNotesFailuresDoNotWrite(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	for _, args := range [][]string{
		{}, {"--initial", "--from", "previous-api"}, {"--from", ""}, {"--initial=false"},
		{"--initial", "--package", "missing"}, {"missing", "--initial"}, {"upstream", "extra", "--initial"},
		{"--from", "missing"}, {"--initial", "--to", "missing"}, {"--initial", "--include-path", "../../escape"},
		{"--initial", "--output", ""}, {"--initial", "--changelog", ""},
	} {
		args = append([]string{"--dir", fixture.Directory, "--output", "not-created/notes.md", "--changelog", "not-created/CHANGELOG.md"}, args...)
		stdout, _, err := executeNotes(t, notesCmd, args...)
		require.Error(t, err, args)
		require.Empty(t, stdout)
		_, err = os.Stat(filepath.Join(fixture.Directory, "not-created"))
		require.ErrorIs(t, err, os.ErrNotExist)
	}

	// A handwritten conflict is found before replacing a pre-existing notes file.
	notesPath := filepath.Join(fixture.Directory, "notes.md")
	require.NoError(t, os.WriteFile(notesPath, []byte("original notes"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(fixture.Directory, "CHANGELOG.md"), []byte("## root-flavorless\n\nHandwritten.\n"), 0o644))
	stdout, _, err := executeNotes(t, notesCmd, "--dir", fixture.Directory, "--initial", "--output", "notes.md", "--changelog", "CHANGELOG.md")
	require.ErrorContains(t, err, "handwritten section")
	require.Empty(t, stdout)
	content, err := os.ReadFile(notesPath)
	require.NoError(t, err)
	require.Equal(t, "original notes", string(content))

	_, _, err = executeNotes(t, notesCmd, "--dir", fixture.Directory, "--initial", "--output", "notes.md", "--changelog", "notes.md")
	require.ErrorContains(t, err, "same file")
}

func TestNotesBundleOnlyAndInitialEndpoint(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	config := types.ReleaseConfig{Bundles: []types.Bundle{{Name: "platform", Path: "bundles/platform", Version: "testing"}}}
	data, err := goyaml.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(fixture.Directory, "releaser.yaml"), data, 0o644))
	stdout, stderr, err := executeNotes(t, bundleNotesCmd, "platform", "--dir", fixture.Directory, "--initial", "--to", fixture.Base)
	require.NoError(t, err)
	require.Empty(t, stderr)
	require.Contains(t, stdout, "## platform-testing")
	require.Contains(t, stdout, "initial fixture")
	require.NotContains(t, stdout, "refresh platform references")
	_, _, err = executeNotes(t, bundleNotesCmd, "--dir", fixture.Directory, "--initial")
	require.Error(t, err)

	// Equal endpoints are a valid empty release.
	stdout, _, err = executeNotes(t, bundleNotesCmd, "platform", "--dir", fixture.Directory, "--from", fixture.Head)
	require.NoError(t, err)
	require.Contains(t, stdout, "No changes matched")
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
