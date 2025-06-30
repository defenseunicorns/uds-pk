// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckCommand(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("release", "check", "base", "-d", "src/test")
	require.NoError(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version 1.0.0-uds.0-base is not tagged")

	stdout, stderr, err = e2e.UDSPK("release", "check", "dummy", "-d", "src/test")
	require.Error(t, err, stdout, stderr)

	require.Contains(t, stdout, "Version 0.0.1-testing-dummy is already tagged")
}

func TestCheckCommandBool(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("release", "check", "base", "-d", "src/test", "-b")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "true\n", stdout)

	stdout, stderr, err = e2e.UDSPK("release", "check", "dummy", "-d", "src/test", "-b")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "false\n", stdout)
}
