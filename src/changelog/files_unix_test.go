//go:build unix

// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteArtifactsUmask(t *testing.T) {
	// Umask is process-wide; isolate each setting from other tests and goroutines.
	mask := os.Getenv("UDS_PK_TEST_UMASK")
	if mask == "" {
		for _, mask := range []string{"077", "027", "022"} {
			t.Run(mask, func(t *testing.T) {
				command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestWriteArtifactsUmask$")
				command.Env = append(os.Environ(), "UDS_PK_TEST_UMASK="+mask)
				output, err := command.CombinedOutput()
				require.NoError(t, err, "%s", output)
			})
		}
		return
	}
	value, err := strconv.ParseInt(mask, 8, 32)
	require.NoError(t, err)
	previous := syscall.Umask(int(value))
	defer syscall.Umask(previous)
	directory := t.TempDir()
	control := filepath.Join(directory, "control.md")
	require.NoError(t, os.WriteFile(control, []byte("normal creation"), 0o644))
	controlInfo, err := os.Stat(control)
	require.NoError(t, err)
	existing := filepath.Join(directory, "existing.md")
	require.NoError(t, os.WriteFile(existing, nil, 0o644))
	require.NoError(t, os.Chmod(existing, 0o640))
	notes, history := filepath.Join(directory, "notes.md"), filepath.Join(directory, "CHANGELOG.md")
	require.NoError(t, WriteArtifacts(Artifact{Path: notes}, Artifact{Path: history}, Artifact{Path: existing}))
	for _, path := range []string{notes, history} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, controlInfo.Mode().Perm(), info.Mode().Perm())
	}
	info, err := os.Stat(existing)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
	matches, err := filepath.Glob(filepath.Join(directory, ".uds-pk-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}
