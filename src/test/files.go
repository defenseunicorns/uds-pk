// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func ReadFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return content
}

func RequireFileContents(t *testing.T, expected map[string]string) {
	t.Helper()
	for path, content := range expected {
		require.Equal(t, content, string(ReadFile(t, path)), path)
	}
}
