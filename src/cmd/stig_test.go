// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/stig"
	"github.com/spf13/cobra"
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

func TestResolveOutputPathsRejectsHardLinkDuplicates(t *testing.T) {
	dir := t.TempDir()
	firstOutput := filepath.Join(dir, "first.cklb")
	secondOutput := filepath.Join(dir, "second.cklb")
	require.NoError(t, os.WriteFile(firstOutput, []byte("existing checklist"), 0o644))
	if err := os.Link(firstOutput, secondOutput); err != nil {
		t.Skipf("hard links not supported: %v", err)
	}

	profiles := []*stig.STIGProfile{
		{ID: stig.ASDSTIGProfileKey},
		{ID: stig.RHEL9STIGProfileKey},
	}

	_, err := resolveOutputPaths("test-app", profiles, []string{firstOutput, secondOutput})
	require.EqualError(t, err, `output paths must be unique: "`+secondOutput+`" is used more than once`)
}

func TestResolveOutputPathsRejectsDanglingSymlinkAliasDuplicates(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "output.cklb")
	firstOutput := filepath.Join(dir, "first.cklb")
	secondOutput := filepath.Join(dir, "second.cklb")
	if err := os.Symlink(target, firstOutput); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if err := os.Symlink(target, secondOutput); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	profiles := []*stig.STIGProfile{
		{ID: stig.ASDSTIGProfileKey},
		{ID: stig.RHEL9STIGProfileKey},
	}

	_, err := resolveOutputPaths("test-app", profiles, []string{firstOutput, secondOutput})
	require.EqualError(t, err, `output paths must be unique: "`+secondOutput+`" is used more than once`)
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

func TestValidateOutputPathsDoNotOverwriteXCCDFsRejectsSymlinkToInput(t *testing.T) {
	dir := t.TempDir()
	xccdfPath := filepath.Join(dir, "input.xml")
	outputPath := filepath.Join(dir, "output.cklb")
	require.NoError(t, os.WriteFile(xccdfPath, []byte("original XCCDF"), 0o644))
	if err := os.Symlink(xccdfPath, outputPath); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	err := validateOutputPathsDoNotOverwriteXCCDFs(
		[]string{outputPath},
		[]string{xccdfPath},
	)
	require.EqualError(t, err, `output path "`+outputPath+`" conflicts with XCCDF input path "`+xccdfPath+`"`)
}

func TestValidateOutputPathsDoNotOverwriteXCCDFsRejectsHardLinkToInput(t *testing.T) {
	dir := t.TempDir()
	xccdfPath := filepath.Join(dir, "input.xml")
	outputPath := filepath.Join(dir, "output.cklb")
	require.NoError(t, os.WriteFile(xccdfPath, []byte("original XCCDF"), 0o644))
	if err := os.Link(xccdfPath, outputPath); err != nil {
		t.Skipf("hard links not supported: %v", err)
	}

	err := validateOutputPathsDoNotOverwriteXCCDFs(
		[]string{outputPath},
		[]string{xccdfPath},
	)
	require.EqualError(t, err, `output path "`+outputPath+`" conflicts with XCCDF input path "`+xccdfPath+`"`)
}

func TestWriteChecklistsRollsBackExistingOutputs(t *testing.T) {
	dir := t.TempDir()
	firstOutput := filepath.Join(dir, "first.cklb")
	secondOutput := filepath.Join(dir, "second.cklb")
	require.NoError(t, os.WriteFile(firstOutput, []byte("original first"), 0o600))
	require.NoError(t, os.WriteFile(secondOutput, []byte("original second"), 0o640))

	checklists := []*generatedChecklist{
		{stigID: stig.ASDSTIGProfileKey, outputPath: firstOutput, destinationPath: firstOutput, data: []byte("new first")},
		{stigID: stig.RHEL9STIGProfileKey, outputPath: secondOutput, destinationPath: secondOutput, data: []byte("new second")},
	}
	writeFile := func(path string, data []byte, mode os.FileMode) error {
		if path == secondOutput && string(data) == "new second" {
			return errors.New("injected write failure")
		}
		return os.WriteFile(path, data, mode)
	}

	err := writeChecklistsWithWriter(&cobra.Command{}, checklists, writeFile)
	require.ErrorContains(t, err, `writing checklist for STIG "rhel9_v2r7": injected write failure`)
	firstData, err := os.ReadFile(firstOutput)
	require.NoError(t, err)
	require.Equal(t, []byte("original first"), firstData)
	secondData, err := os.ReadFile(secondOutput)
	require.NoError(t, err)
	require.Equal(t, []byte("original second"), secondData)
	firstInfo, err := os.Stat(firstOutput)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), firstInfo.Mode().Perm())
	secondInfo, err := os.Stat(secondOutput)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), secondInfo.Mode().Perm())
}

func TestWriteChecklistsPreservesHardLinks(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "output.cklb")
	linkedPath := filepath.Join(dir, "linked.cklb")
	require.NoError(t, os.WriteFile(outputPath, []byte("original checklist"), 0o640))
	if err := os.Link(outputPath, linkedPath); err != nil {
		t.Skipf("hard links not supported: %v", err)
	}

	checklist := &generatedChecklist{
		stigID:          stig.ASDSTIGProfileKey,
		outputPath:      outputPath,
		destinationPath: outputPath,
		data:            []byte("new checklist"),
	}
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	require.NoError(t, writeChecklists(cmd, []*generatedChecklist{checklist}))

	outputInfo, err := os.Stat(outputPath)
	require.NoError(t, err)
	linkedInfo, err := os.Stat(linkedPath)
	require.NoError(t, err)
	require.True(t, os.SameFile(outputInfo, linkedInfo))
	linkedData, err := os.ReadFile(linkedPath)
	require.NoError(t, err)
	require.Equal(t, []byte("new checklist"), linkedData)
}
