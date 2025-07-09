package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareScansCommandSimple(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/alpine_3.17.json", "--output", "simple")
	require.NoError(t, err, stdout, stderr)

	expectedNew := "New vulnerabilities: 5"
	expectedFixed := "Fixed vulnerabilities: 14"
	expectedExisting := "Existing vulnerabilities: 4"

	assert.Contains(t, stdout, expectedNew)
	assert.Contains(t, stdout, expectedFixed)
	assert.Contains(t, stdout, expectedExisting)
}

func TestCompareScansCommandSimpleDifferentImages(t *testing.T) {
	_, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/busybox.json", "--output", "simple")
	require.Error(t, err)
	assert.Contains(t, stderr, "these scans are not for the same image")
}

func TestCompareScansCommandSimpleAllowDifferentImages(t *testing.T) {
	stdout, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/busybox.json", "--output", "simple", "--allow-different-images")
	require.NoError(t, err, stdout, stderr)

	expectedNew := "New vulnerabilities: 4"
	expectedFixed := "Fixed vulnerabilities: 18"
	expectedExisting := "Existing vulnerabilities: 0"

	assert.Contains(t, stdout, expectedNew)
	assert.Contains(t, stdout, expectedFixed)
	assert.Contains(t, stdout, expectedExisting)
}
