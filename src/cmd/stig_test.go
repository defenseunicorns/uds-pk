// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"os"
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

func TestResolveOutputPathsRejectsSymlinkAliasDuplicates(t *testing.T) {
	tempDir := t.TempDir()
	realDir := filepath.Join(tempDir, "real")
	linkDir := filepath.Join(tempDir, "link")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	profiles := []*stig.STIGProfile{
		{ID: stig.ASDSTIGProfileKey},
		{ID: stig.RHEL9STIGProfileKey},
	}
	realOutput := filepath.Join(realDir, "output.cklb")
	symlinkOutput := filepath.Join(linkDir, "output.cklb")

	_, err := resolveOutputPaths("test-app", profiles, []string{realOutput, symlinkOutput})
	require.EqualError(t, err, `output paths must be unique: "`+symlinkOutput+`" is used more than once`)
}

func TestValidateOutputPathsDoNotOverwriteXCCDFsRejectsCrossEntryCollision(t *testing.T) {
	dir := t.TempDir()
	firstXCCDF := filepath.Join(dir, "first.xml")
	secondXCCDF := filepath.Join(dir, "second.xml")
	outputPath := filepath.Join(dir, "output.cklb")

	err := validateOutputPathsDoNotOverwriteXCCDFs(
		[]string{secondXCCDF, outputPath},
		[]string{firstXCCDF, secondXCCDF},
	)
	require.EqualError(t, err, `output path "`+secondXCCDF+`" conflicts with XCCDF input path "`+secondXCCDF+`"`)
}
