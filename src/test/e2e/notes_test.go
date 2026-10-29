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
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/go-git/go-git/v5/plumbing"
	goyaml "github.com/goccy/go-yaml"
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

func TestNotesCLISelectorsAndReadOnlyHistory(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	outside := t.TempDir()
	relativeDirectory, err := filepath.Rel(outside, fixture.Directory)
	require.NoError(t, err)
	refs := notesRefs(t, fixture)
	configPath := filepath.Join(fixture.Directory, "releaser.yaml")
	configBefore, err := os.ReadFile(configPath)
	require.NoError(t, err)
	tests := []struct {
		args    []string
		tag     string
		include string
		exclude string
	}{
		{[]string{"release", "notes", "upstream", "--verbose"}, "2.0.0-upstream", "retry failed jobs", "initial fixture"},
		{[]string{"release", "notes"}, "root-flavorless", "refresh platform references", "initial fixture"},
		{[]string{"release", "notes", "upstream", "--package", "api"}, "api-2.0.0-upstream", "configure API replicas", "retry failed jobs"},
		{[]string{"release", "notes", "--package", "api"}, "api-api-flavorless", "expose the health endpoint", "retry failed jobs"},
		{[]string{"release", "notes", "--package", "worker"}, "worker-3.0.0", "retry failed jobs", "expose the health endpoint"},
		{[]string{"release", "bundle", "notes", "platform"}, "platform-4.0.0", "refresh platform references", "expose the health endpoint"},
		{[]string{"release", "bundle", "notes", "platform-test"}, "platform-test-testing", "No changes matched", "refresh platform references"},
	}
	for _, current := range tests {
		args := append(append([]string(nil), current.args...), "-d", relativeDirectory, "--from", "previous-api")
		stdout, stderr, err := runNotesBinary(t, outside, args...)
		require.NoError(t, err, stderr)
		require.Empty(t, stderr)
		require.True(t, strings.HasPrefix(stdout, "# Release notes\n\n"), stdout)
		require.Contains(t, stdout, "## "+current.tag+"\n")
		require.Contains(t, stdout, current.include)
		require.NotContains(t, stdout, current.exclude)
		require.NotContains(t, stdout, "Warning:")
		require.NotContains(t, stdout, "fixture-token")
	}
	require.Equal(t, refs, notesRefs(t, fixture))
	configAfter, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.Equal(t, configBefore, configAfter)
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
	notes, err := os.ReadFile(filepath.Join(fixture.Directory, "notes", "api.md"))
	require.NoError(t, err)
	require.Contains(t, string(notes), "initialize the shared runtime")
	require.NotContains(t, string(notes), "retry failed jobs")
	historyPath := filepath.Join(fixture.Directory, "CHANGELOG.md")
	history, err := os.ReadFile(historyPath)
	require.NoError(t, err)
	_, stderr, err = runNotesBinary(t, outside, args...)
	require.NoError(t, err, stderr)
	repeated, err := os.ReadFile(historyPath)
	require.NoError(t, err)
	require.Equal(t, history, repeated)
	_, err = os.Stat(filepath.Join(outside, "notes"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestNotesCLIErrorsKeepStdoutAndFilesClean(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	outside := t.TempDir()
	for _, flags := range [][]string{
		{}, {"--from", "missing"}, {"--initial", "--from", "previous-api"}, {"--initial", "--include-path", "../../escape"},
		{"--initial", "--output", ""}, {"--initial", "--output", "not-created/CHANGELOG.md"},
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

func TestNotesCLIBundleOnlyInitialRelease(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	var config types.ReleaseConfig
	require.NoError(t, utils.LoadYaml(filepath.Join(fixture.Directory, "releaser.yaml"), &config))
	config.Flavors, config.Packages = nil, nil
	data, err := goyaml.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(fixture.Directory, "releaser.yaml"), data, 0o644))
	stdout, stderr, err := runNotesBinary(t, t.TempDir(), "release", "bundle", "notes", "platform", "--dir", fixture.Directory, "--initial", "--to", fixture.Base)
	require.NoError(t, err, stderr)
	require.Empty(t, stderr)
	require.Contains(t, stdout, "## platform-4.0.0\n")
	require.Contains(t, stdout, "Initial release (all reachable history)")
	require.Contains(t, stdout, "initial fixture")
	require.NotContains(t, stdout, "refresh platform references")
}

func TestNotesCLIHandwrittenReferenceConflicts(t *testing.T) {
	for _, heading := range []string{
		"## [root-flavorless] - 2026-10-29",
		"### [root-flavorless](https://example.test/release)",
		"root-flavorless\n---",
	} {
		t.Run(heading, func(t *testing.T) {
			fixture := test.CreateNotesFixture(t)
			notesPath := filepath.Join(fixture.Directory, "notes.md")
			historyPath := filepath.Join(fixture.Directory, "CHANGELOG.md")
			history := []byte("# Changelog\n\n" + heading + "\n\nHandwritten.\n\n[root-flavorless]: https://example.test/release\n")
			require.NoError(t, os.WriteFile(notesPath, []byte("original notes"), 0o644))
			require.NoError(t, os.WriteFile(historyPath, history, 0o644))
			stdout, stderr, err := runNotesBinary(t, t.TempDir(), "release", "notes", "--dir", fixture.Directory, "--initial", "--output", "notes.md", "--changelog", "CHANGELOG.md")
			require.Error(t, err)
			require.Empty(t, stdout)
			require.Contains(t, stderr, "handwritten section")
			unchanged, err := os.ReadFile(historyPath)
			require.NoError(t, err)
			require.Equal(t, history, unchanged)
			unchanged, err = os.ReadFile(notesPath)
			require.NoError(t, err)
			require.Equal(t, "original notes", string(unchanged))
		})
	}
}

func TestNotesCLIOpenFenceDoesNotWrite(t *testing.T) {
	for _, fence := range []string{"```text", "~~~text"} {
		t.Run(fence, func(t *testing.T) {
			fixture := test.CreateNotesFixture(t)
			notesPath := filepath.Join(fixture.Directory, "notes.md")
			historyPath := filepath.Join(fixture.Directory, "CHANGELOG.md")
			history := []byte("# Changelog\n\n" + fence + "\nHandwritten example.\n")
			require.NoError(t, os.WriteFile(notesPath, []byte("original notes"), 0o644))
			require.NoError(t, os.WriteFile(historyPath, history, 0o644))
			for range 2 {
				stdout, stderr, err := runNotesBinary(t, t.TempDir(), "release", "notes", "--dir", fixture.Directory, "--initial", "--output", "notes.md", "--changelog", "CHANGELOG.md")
				require.Error(t, err)
				require.Empty(t, stdout)
				require.Contains(t, stderr, "close any open code fence")
				unchanged, err := os.ReadFile(historyPath)
				require.NoError(t, err)
				require.Equal(t, history, unchanged)
				unchanged, err = os.ReadFile(notesPath)
				require.NoError(t, err)
				require.Equal(t, "original notes", string(unchanged))
			}
		})
	}
}

func TestNotesCLIOutputCaseAliases(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		existing bool
	}{{name: "new files"}, {name: "existing file", existing: true}} {
		t.Run(scenario.name, func(t *testing.T) {
			existing := scenario.existing
			fixture := test.CreateNotesFixture(t)
			probe := filepath.Join(fixture.Directory, "case-probe")
			require.NoError(t, os.WriteFile(probe, nil, 0o600))
			_, probeErr := os.Stat(filepath.Join(fixture.Directory, "CASE-PROBE"))
			aliases := probeErr == nil
			if !aliases {
				require.ErrorIs(t, probeErr, os.ErrNotExist)
			}
			output, history := "artifacts/notes.md", "ARTIFACTS/NOTES.md"
			if existing {
				output, history = "notes.md", "NOTES.md"
				require.NoError(t, os.WriteFile(filepath.Join(fixture.Directory, output), []byte("original notes"), 0o644))
			}
			stdout, stderr, err := runNotesBinary(t, t.TempDir(), "release", "notes", "--dir", fixture.Directory, "--initial", "--output", output, "--changelog", history)
			require.Empty(t, stdout)
			if aliases {
				require.Error(t, err)
				require.Contains(t, stderr, "same file")
				if existing {
					unchanged, err := os.ReadFile(filepath.Join(fixture.Directory, output))
					require.NoError(t, err)
					require.Equal(t, "original notes", string(unchanged))
				} else {
					_, err := os.Stat(filepath.Join(fixture.Directory, "artifacts"))
					require.ErrorIs(t, err, os.ErrNotExist)
				}
			} else {
				require.NoError(t, err, stderr)
				require.Empty(t, stderr)
				notes, err := os.ReadFile(filepath.Join(fixture.Directory, output))
				require.NoError(t, err)
				require.True(t, strings.HasPrefix(string(notes), "# Release notes\n"))
				changelog, err := os.ReadFile(filepath.Join(fixture.Directory, history))
				require.NoError(t, err)
				require.Contains(t, string(changelog), "<!-- uds-pk:release ")
			}
		})
	}
}
