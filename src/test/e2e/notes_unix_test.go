//go:build unix

// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/defenseunicorns/uds-pk/src/test"
	"github.com/stretchr/testify/require"
)

func TestNotesCLIRejectsFIFODestinations(t *testing.T) {
	for _, flag := range []string{"--output", "--changelog"} {
		for _, symlink := range []bool{false, true} {
			t.Run(flag+map[bool]string{false: "/fifo", true: "/symlink"}[symlink], func(t *testing.T) {
				fixture := test.CreateNotesFixture(t)
				fifo := filepath.Join(fixture.Directory, "fifo")
				require.NoError(t, syscall.Mkfifo(fifo, 0o600))
				path := fifo
				if symlink {
					path = filepath.Join(fixture.Directory, "link")
					require.NoError(t, os.Symlink(fifo, path))
				}
				other := filepath.Join(fixture.Directory, "other.md")
				require.NoError(t, os.WriteFile(other, nil, 0o600))
				otherFlag := "--output"
				if flag == otherFlag {
					otherFlag = "--changelog"
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, e2e.UDSPKBinPath, "release", "notes", "--dir", fixture.Directory, "--initial", flag, path, otherFlag, other)
				output, err := command.CombinedOutput()
				require.NoError(t, ctx.Err(), "command blocked on FIFO: %s", output)
				require.Error(t, err)
				require.Contains(t, string(output), "not a regular file")
				test.RequireFileContents(t, map[string]string{other: ""})
			})
		}
	}
}
