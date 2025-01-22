// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyBadgeGood(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("verify-badge", "-d", "src/test/verify/mattermost-good")
	require.NoError(t, err, stdout, stderr)
	require.Contains(t, stderr, "Namespaces (1): [mattermost]")
}

func TestVerifyBadgeWarnings(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("verify-badge", "-d", "src/test/verify/mattermost-warnings")
	require.NoError(t, err, stdout, stderr)
	require.Contains(t, stderr, "Namespaces (1): [mattermost]")
	require.Contains(t, stderr, "Manifests present in src/test/verify/mattermost-warnings/common/zarf.yaml")
	require.Contains(t, stderr, "Manifests present in src/test/verify/mattermost-warnings/zarf.yaml")
}

func TestVerifyBadgeBad(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("verify-badge", "-d", "src/test/verify/mattermost-errors-and-warnings")
	require.Error(t, err, stdout, stderr)
	require.Contains(t, stderr, "Namespaces (1): [mattermost]")
	require.Contains(t, stderr, "Manifests present in src/test/verify/mattermost-errors-and-warnings/common/zarf.yaml")
	require.Contains(t, stderr, "Manifests present in src/test/verify/mattermost-errors-and-warnings/zarf.yaml")
	require.Contains(t, stderr, "No flavors defined in in src/test/verify/mattermost-errors-and-warnings/zarf.yaml")
}
