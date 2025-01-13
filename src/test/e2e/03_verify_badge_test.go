// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyBadgeGoodFailFalse(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("verify-badge", "-d", "src/test/verify/mattermost-good")
	require.NoError(t, err, stdout, stderr)
}
func TestVerifyBadgeGoodFailTrue(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("verify-badge", "-d", "src/test/verify/mattermost-good", "-f")
	require.NoError(t, err, stdout, stderr)
}

func TestVerifyBadgeBadFailTrue(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("verify-badge", "-d", "src/test/verify/mattermost-bad", "-f")
	require.Error(t, err, stdout, stderr)
	require.Contains(t, stderr, "Manifests present in src/test/verify/mattermost-bad/common/zarf.yaml")
	require.Contains(t, stderr, "Manifests present in src/test/verify/mattermost-bad/zarf.yaml")
	require.Contains(t, stderr, "No flavors defined in in src/test/verify/mattermost-bad/zarf.yaml")
}

func TestVerifyBadgeBadFailFalse(t *testing.T) {
	stdout, stderr, err := e2e.UDSPK("verify-badge", "-d", "src/test/verify/mattermost-bad")
	require.NoError(t, err, stdout, stderr)
	require.Contains(t, stderr, "Manifests present in src/test/verify/mattermost-bad/common/zarf.yaml")
	require.Contains(t, stderr, "Manifests present in src/test/verify/mattermost-bad/zarf.yaml")
	require.Contains(t, stderr, "No flavors defined in in src/test/verify/mattermost-bad/zarf.yaml")
}
