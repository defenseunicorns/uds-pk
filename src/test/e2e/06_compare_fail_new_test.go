package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareScansCommandFailOnNewVulns(t *testing.T) {
	_, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "-f", "scans/alpine_3.16.json", "scans/alpine_3.17.json", "--fail-on-new-vulns")
	require.Error(t, err)
	assert.Contains(t, stderr, "new vulnerabilities found in the new scan compared to the base scan")
}

func TestCompareScansCommandFailOnNewVulnsDifferentImages(t *testing.T) {
	_, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/busybox.json", "--fail-on-new-vulns")
	require.Error(t, err)
	assert.Contains(t, stderr, "these scans are not for the same image")
}

func TestCompareScansCommandFailOnNewVulnsAllowDifferentImages(t *testing.T) {
	_, stderr, err := e2e.UDSPKDir("src/test", "compare-scans", "scans/alpine_3.16.json", "scans/busybox.json", "--fail-on-new-vulns", "--allow-different-images")
	require.Error(t, err)
	assert.Contains(t, stderr, "new vulnerabilities found in the new scan compared to the base scan")
}
