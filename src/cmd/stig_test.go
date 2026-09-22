// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/stig"
	"github.com/stretchr/testify/require"
)

func TestValidateUniqueSTIGs(t *testing.T) {
	profiles := []*stig.STIGProfile{
		{ID: stig.ASDSTIGProfileKey},
		{ID: stig.ASDSTIGProfileKey},
	}
	require.EqualError(t, validateUniqueSTIGs(profiles), `profile contains duplicate STIG "asd_v6r4"`)
}

func TestResolveOutputPathsRejectsDuplicates(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "output.cklb")
	profiles := []*stig.STIGProfile{
		{ID: stig.ASDSTIGProfileKey},
		{ID: stig.RHEL9STIGProfileKey},
	}

	_, err := resolveOutputPaths("test-app", profiles, []string{outputPath, outputPath})
	require.EqualError(t, err, `output paths must be unique: "`+outputPath+`" is used more than once`)
}
