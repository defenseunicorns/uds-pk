// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShowCommand(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "show", "base")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "1.0.0-uds.0-base\n", stdout)
}

func TestShowCommandVersionFlag(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "show", "base", "--version-only")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "1.0.0-uds.0\n", stdout)
}
