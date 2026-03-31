// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var expectedTableHeaders = []string{
	"ID", "Severity", "URL",
}

func TestCompareScansCommand(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/alpine_3.17.json")
	require.NoError(t, err, stdout, stderr)

	expectedHeader := "### alpine `3.16` -> `3.17`"

	expectedNew := "New vulnerabilities: 5"
	expectedFixed := "Fixed vulnerabilities: 14"
	expectedExisting := "Existing vulnerabilities: 4"

	assert.Contains(t, stdout, expectedHeader)
	assert.Contains(t, stdout, expectedNew)
	assert.Contains(t, stdout, expectedFixed)
	assert.Contains(t, stdout, expectedExisting)

	for _, header := range expectedTableHeaders {
		assert.Contains(t, stdout, strings.ToUpper(header))
	}
}

func TestCompareScansCommandRegistryPrefix(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/docker.io_alpine_3.17.json")
	require.NoError(t, err, stdout, stderr)

	expectedHeader := "### alpine `3.16` -> `3.17`"

	expectedNew := "New vulnerabilities: 5"
	expectedFixed := "Fixed vulnerabilities: 14"
	expectedExisting := "Existing vulnerabilities: 4"

	assert.Contains(t, stdout, expectedHeader)
	assert.Contains(t, stdout, expectedNew)
	assert.Contains(t, stdout, expectedFixed)
	assert.Contains(t, stdout, expectedExisting)

	for _, header := range expectedTableHeaders {
		assert.Contains(t, stdout, strings.ToUpper(header))
	}
}

func TestCompareScansCommandDifferentImages(t *testing.T) {
	_, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/busybox.json")
	require.Error(t, err)
	require.Contains(t, stderr, "these scans are not for the same image")
}

func TestCompareScansCommandAllowDifferentImages(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/busybox.json", "--allow-different-images")
	require.NoError(t, err, stdout, stderr)

	expectedHeader := "### `alpine:3.16` -> `busybox:1.36.1`"

	expectedNew := "New vulnerabilities: 4"
	expectedFixed := "Fixed vulnerabilities: 18"
	expectedExisting := "Existing vulnerabilities: 0"

	assert.Contains(t, stdout, expectedHeader)
	assert.Contains(t, stdout, expectedNew)
	assert.Contains(t, stdout, expectedFixed)
	assert.Contains(t, stdout, expectedExisting)

	for _, header := range expectedTableHeaders {
		assert.Contains(t, stdout, strings.ToUpper(header))
	}
}
