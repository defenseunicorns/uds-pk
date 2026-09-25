// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func commandResultXML(status string, ruleID string) string {
	return `<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="benchmark"><TestResult id="run"><rule-result idref="` + ruleID + `"><result>` + status + `</result></rule-result></TestResult></Benchmark>`
}

func writeCommandResult(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestCompareResultsCommandWritesEvidence(t *testing.T) {
	base := writeCommandResult(t, "base.xml", commandResultXML("fail", "rule"))
	newResults := writeCommandResult(t, "new.xml", commandResultXML("pass", "rule"))
	evidence := filepath.Join(t.TempDir(), "evidence.txt")
	command := compareResultsCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetArgs([]string{base, newResults, "--output", evidence})
	require.NoError(t, command.Execute())
	contents, err := os.ReadFile(evidence)
	require.NoError(t, err)
	require.Equal(t, stdout.String(), string(contents))
	require.Contains(t, stdout.String(), "IMPROVEMENTS (1):")
	require.Contains(t, stdout.String(), "PASS: no XCCDF regressions detected.")
}

func TestCompareResultsCommandReturnsRegressionExitCode(t *testing.T) {
	base := writeCommandResult(t, "base.xml", commandResultXML("pass", "rule"))
	newResults := writeCommandResult(t, "new.xml", commandResultXML("fail", "rule"))
	command := compareResultsCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetArgs([]string{base, newResults})
	err := command.Execute()
	var coded *exitCodeError
	require.True(t, errors.As(err, &coded))
	require.Equal(t, 1, coded.ExitCode())
	require.Contains(t, stdout.String(), "FAIL: 1 XCCDF regression(s) detected.")
}

func TestCompareResultsCommandReturnsInputExitCode(t *testing.T) {
	base := writeCommandResult(t, "base.xml", commandResultXML("pass", "base-rule"))
	newResults := writeCommandResult(t, "new.xml", commandResultXML("pass", "new-rule"))
	command := compareResultsCmd()
	command.SetArgs([]string{base, newResults})
	err := command.Execute()
	var coded *exitCodeError
	require.True(t, errors.As(err, &coded))
	require.Equal(t, 2, coded.ExitCode())
}

func TestExitCode(t *testing.T) {
	require.Equal(t, 1, exitCode(errors.New("ordinary error")))
	require.Equal(t, 1, exitCode(newExitCodeError(1, errors.New("regression"))))
	require.Equal(t, 2, exitCode(newExitCodeError(2, errors.New("input error"))))
}

func TestCompareResultsCommandReturnsEvidenceWriteExitCode(t *testing.T) {
	base := writeCommandResult(t, "base.xml", commandResultXML("pass", "rule"))
	newResults := writeCommandResult(t, "new.xml", commandResultXML("pass", "rule"))
	command := compareResultsCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetArgs([]string{base, newResults, "--output", filepath.Join(t.TempDir(), "missing", "evidence.txt")})

	err := command.Execute()
	var coded *exitCodeError
	require.True(t, errors.As(err, &coded))
	require.Equal(t, 2, coded.ExitCode())
	require.Empty(t, stdout.String())
}
