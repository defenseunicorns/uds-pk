// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func resultFixture(namespace string, rows string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<Benchmark xmlns="%s" id="benchmark"><title>Benchmark title</title><TestResult id="run-1" start-time="2026-01-01T00:00:00Z" end-time="2026-01-01T00:01:00Z"><title>Run title</title><profile idref="profile-a"/><target> target-b </target><target>target-a</target>%s</TestResult></Benchmark>`, namespace, rows)
}

func resultRow(id string, status ResultStatus, instance string) string {
	return fmt.Sprintf(`<rule-result idref="%s"><result> %s </result>%s</rule-result>`, id, status, instance)
}

func writeResultFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "results.xml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestLoadXCCDFResults_AllStatusesAndMetadata(t *testing.T) {
	rows := ""
	for index, status := range orderedResultStatuses {
		rows += resultRow(fmt.Sprintf("rule-%d", index), status, "")
	}
	rows += resultRow("multi", ResultPass, `<instance context="user"> alice </instance>`)
	rows += resultRow("multi", ResultFail, `<instance context="user"> bob </instance>`)

	set, err := LoadXCCDFResults(writeResultFixture(t, resultFixture(xccdfNamespace12, rows)))
	require.NoError(t, err)
	require.Equal(t, "benchmark", set.BenchmarkID)
	require.Equal(t, "run-1", set.TestResultID)
	require.Equal(t, "profile-a", set.ProfileID)
	require.Equal(t, "2026-01-01T00:00:00Z", set.StartTime)
	require.Equal(t, []string{"target-a", "target-b"}, set.Targets)
	require.Len(t, set.RuleResults, len(orderedResultStatuses)+2)
	require.Equal(t, ResultFail, set.RuleResults["rule-1"].Status)
	require.Contains(t, set.RuleResults, `multi [name="alice",context="user",parent=""]`)
	require.Contains(t, set.RuleResults, `multi [name="bob",context="user",parent=""]`)
}

func TestLoadXCCDFResults_XCCDF11PrefixedNamespace(t *testing.T) {
	content := `<?xml version="1.0"?><xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.1" id="benchmark"><xccdf:TestResult id="run"><xccdf:rule-result idref="rule"><xccdf:result>pass</xccdf:result></xccdf:rule-result></xccdf:TestResult></xccdf:Benchmark>`
	set, err := LoadXCCDFResults(writeResultFixture(t, content))
	require.NoError(t, err)
	require.Equal(t, ResultPass, set.RuleResults["rule"].Status)
}

func TestLoadXCCDFResults_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "malformed", content: `<Benchmark`},
		{name: "wrong namespace", content: resultFixture("urn:invalid", resultRow("rule", ResultPass, ""))},
		{name: "no test result", content: `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="benchmark"/>`},
		{name: "multiple results", content: `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="benchmark"><TestResult id="one"/><TestResult id="two"/></Benchmark>`},
		{name: "no rule results", content: resultFixture(xccdfNamespace12, "")},
		{name: "missing id", content: resultFixture(xccdfNamespace12, `<rule-result><result>pass</result></rule-result>`)},
		{name: "invalid status", content: resultFixture(xccdfNamespace12, `<rule-result idref="rule"><result>other</result></rule-result>`)},
		{name: "uppercase status", content: resultFixture(xccdfNamespace12, `<rule-result idref="rule"><result>PASS</result></rule-result>`)},
		{name: "foreign TestResult", content: `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:foreign="urn:foreign" id="benchmark"><foreign:TestResult id="run"><rule-result idref="rule"><result>pass</result></rule-result></foreign:TestResult></Benchmark>`},
		{name: "foreign result", content: `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:foreign="urn:foreign" id="benchmark"><TestResult id="run"><rule-result idref="rule"><foreign:result>pass</foreign:result></rule-result></TestResult></Benchmark>`},
		{name: "duplicate", content: resultFixture(xccdfNamespace12, resultRow("rule", ResultPass, "")+resultRow("rule", ResultFail, ""))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadXCCDFResults(writeResultFixture(t, test.content))
			require.Error(t, err)
		})
	}
}

func TestCompareXCCDFResults_AllPairs(t *testing.T) {
	for _, before := range orderedResultStatuses {
		for _, after := range orderedResultStatuses {
			base := &XCCDFResultSet{
				RuleResults: map[string]XCCDFRuleResult{
					"rule": {Identity: "rule", Status: before},
				},
			}
			newResults := &XCCDFResultSet{
				RuleResults: map[string]XCCDFRuleResult{
					"rule": {Identity: "rule", Status: after},
				},
			}
			comparison, err := CompareXCCDFResults(base, newResults)
			require.NoError(t, err)

			wantUnchanged, wantRegressions, wantImprovements, wantReclassifications := 0, 0, 0, 0
			if before == after {
				wantUnchanged = 1
			} else {
				beforeTier, _ := resultStatusTier(before)
				afterTier, _ := resultStatusTier(after)
				switch {
				case afterTier < beforeTier:
					wantRegressions = 1
					require.Equal(t, Regression, comparison.Changes[0].Classification)
				case afterTier > beforeTier:
					wantImprovements = 1
					require.Equal(t, Improvement, comparison.Changes[0].Classification)
				default:
					wantReclassifications = 1
					require.Equal(t, Reclassification, comparison.Changes[0].Classification)
				}
			}

			require.Equal(t, wantUnchanged, comparison.UnchangedCount, "%s -> %s", before, after)
			require.Equal(t, wantRegressions, comparison.RegressionCount, "%s -> %s", before, after)
			require.Equal(t, wantImprovements, comparison.ImprovementCount, "%s -> %s", before, after)
			require.Equal(t, wantReclassifications, comparison.ReclassifyCount, "%s -> %s", before, after)
			require.Len(t, comparison.Changes, wantRegressions+wantImprovements+wantReclassifications, "%s -> %s", before, after)
		}
	}
}

func TestCompareXCCDFResultsAndRender(t *testing.T) {
	base := &XCCDFResultSet{
		SourcePath:   "base.xml",
		BenchmarkID:  "benchmark",
		TestResultID: "base",
		RuleResults: map[string]XCCDFRuleResult{
			"a": {Identity: "a", Status: ResultPass},
			"b": {Identity: "b", Status: ResultFail},
			"c": {Identity: "c", Status: ResultPass},
			"d": {Identity: "d", Status: ResultNotSelected},
		},
	}
	newResults := &XCCDFResultSet{
		SourcePath:   "new.xml",
		BenchmarkID:  "benchmark",
		TestResultID: "new",
		RuleResults: map[string]XCCDFRuleResult{
			"a": {Identity: "a", Status: ResultFail},
			"b": {Identity: "b", Status: ResultFixed},
			"c": {Identity: "c", Status: ResultInformational},
			"d": {Identity: "d", Status: ResultNotSelected},
		},
	}
	comparison, err := CompareXCCDFResults(base, newResults)
	require.NoError(t, err)
	require.Equal(t, 1, comparison.UnchangedCount)
	require.Equal(t, 1, comparison.RegressionCount)
	require.Equal(t, 1, comparison.ImprovementCount)
	require.Equal(t, 1, comparison.ReclassifyCount)
	require.True(t, comparison.HasRegressions())

	report := RenderXCCDFComparison(comparison)
	for _, status := range orderedResultStatuses {
		require.Contains(t, report, string(status))
	}
	require.Contains(t, report, "REGRESSIONS (1):\n  a")
	require.Contains(t, report, "IMPROVEMENTS (1):\n  b")
	require.Contains(t, report, "RECLASSIFICATIONS (1):\n  c")
	require.Contains(t, report, "FAIL: 1 XCCDF regression(s) detected.")
}

func TestCompareXCCDFResults_RequiresEquivalentIdentities(t *testing.T) {
	base := &XCCDFResultSet{
		RuleResults: map[string]XCCDFRuleResult{
			"base-only": {Identity: "base-only", Status: ResultPass},
		},
	}
	newResults := &XCCDFResultSet{
		RuleResults: map[string]XCCDFRuleResult{
			"new-only": {Identity: "new-only", Status: ResultPass},
		},
	}
	_, err := CompareXCCDFResults(base, newResults)
	var incompatible *IncompatibleResultSetsError
	require.True(t, errors.As(err, &incompatible))
	require.Equal(t, []string{"base-only"}, incompatible.BaseOnly)
	require.Equal(t, []string{"new-only"}, incompatible.NewOnly)
}

func TestCompareXCCDFResults_TreatsUnknownAsFailing(t *testing.T) {
	base := &XCCDFResultSet{
		RuleResults: map[string]XCCDFRuleResult{
			"rule": {Identity: "rule", Status: ResultUnknown},
		},
	}
	newResults := &XCCDFResultSet{
		RuleResults: map[string]XCCDFRuleResult{
			"rule": {Identity: "rule", Status: ResultNotChecked},
		},
	}
	comparison, err := CompareXCCDFResults(base, newResults)
	require.NoError(t, err)
	require.Zero(t, comparison.RegressionCount)
	require.Equal(t, 1, comparison.ImprovementCount)
	require.Zero(t, comparison.ReclassifyCount)
	require.Equal(t, Improvement, comparison.Changes[0].Classification)
}

func TestCompareXCCDFResults_ClassifiesNotSelectedTransitions(t *testing.T) {
	tests := []struct {
		name                    string
		base                    ResultStatus
		candidate               ResultStatus
		classification          ChangeClassification
		regressions             int
		improvements            int
		reclassifications       int
	}{
		{
			name:              "not selected to fail",
			base:              ResultNotSelected,
			candidate:         ResultFail,
			classification:    Regression,
			regressions:       1,
		},
		{
			name:           "fail to not selected",
			base:           ResultFail,
			candidate:      ResultNotSelected,
			classification: Improvement,
			improvements:   1,
		},
		{
			name:              "not selected to not checked",
			base:              ResultNotSelected,
			candidate:         ResultNotChecked,
			classification:    Reclassification,
			reclassifications: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := &XCCDFResultSet{
				RuleResults: map[string]XCCDFRuleResult{
					"rule": {Identity: "rule", Status: test.base},
				},
			}
			newResults := &XCCDFResultSet{
				RuleResults: map[string]XCCDFRuleResult{
					"rule": {Identity: "rule", Status: test.candidate},
				},
			}

			comparison, err := CompareXCCDFResults(base, newResults)
			require.NoError(t, err)
			require.Equal(t, test.classification, comparison.Changes[0].Classification)
			require.Equal(t, test.regressions, comparison.RegressionCount)
			require.Equal(t, test.improvements, comparison.ImprovementCount)
			require.Equal(t, test.reclassifications, comparison.ReclassifyCount)
			require.Equal(t, test.regressions > 0, comparison.HasRegressions())
		})
	}
}

func TestRenderXCCDFComparison_IsDeterministic(t *testing.T) {
	set := &XCCDFResultSet{
		SourcePath:   "same.xml",
		TestResultID: "run",
		RuleResults: map[string]XCCDFRuleResult{
			"rule": {Identity: "rule", Status: ResultPass},
		},
	}
	comparison, err := CompareXCCDFResults(set, set)
	require.NoError(t, err)
	first := RenderXCCDFComparison(comparison)
	require.Equal(t, first, RenderXCCDFComparison(comparison))
	require.True(t, strings.HasSuffix(first, "PASS: no XCCDF regressions detected.\n"))
}

func TestCompareXCCDFResults_RequiresMatchingComparisonMetadata(t *testing.T) {
	base := &XCCDFResultSet{
		BenchmarkID:      "benchmark-a",
		BenchmarkVersion: "1",
		ProfileID:        "profile-a",
		RuleResults: map[string]XCCDFRuleResult{
			"rule": {Identity: "rule", Status: ResultPass},
		},
	}
	newResults := &XCCDFResultSet{
		BenchmarkID:      "benchmark-b",
		BenchmarkVersion: "2",
		ProfileID:        "profile-b",
		RuleResults: map[string]XCCDFRuleResult{
			"rule": {Identity: "rule", Status: ResultPass},
		},
	}

	_, err := CompareXCCDFResults(base, newResults)
	var incompatible *IncompatibleResultSetsError
	require.True(t, errors.As(err, &incompatible))
	require.Equal(t, []string{
		`benchmark ID differs (base="benchmark-a", new="benchmark-b")`,
		`benchmark version differs (base="1", new="2")`,
		`profile ID differs (base="profile-a", new="profile-b")`,
	}, incompatible.Metadata)
}

func TestCanonicalInstanceNormalizesWhitespaceAndEscapesDelimiters(t *testing.T) {
	instance := canonicalInstance([]xccdfInstance{{
		Text:          "  one\n two;three  ",
		Context:       " context,one ",
		ParentContext: " parent=one ",
	}})
	require.Equal(t, `name="one two;three",context="context,one",parent="parent=one"`, instance)
}

func TestCanonicalInstanceSortsRepeatedInstances(t *testing.T) {
	first := canonicalInstance([]xccdfInstance{
		{Text: "beta", Context: "user"},
		{Text: "alpha", Context: "user"},
	})
	second := canonicalInstance([]xccdfInstance{
		{Text: "alpha", Context: "user"},
		{Text: "beta", Context: "user"},
	})
	require.Equal(t, second, first)
}

func TestRenderXCCDFComparison_Golden(t *testing.T) {
	base := &XCCDFResultSet{
		SourcePath:       "base.xml",
		BenchmarkID:      "bench",
		BenchmarkVersion: "1",
		TestResultID:     "old",
		ProfileID:        "profile",
		Targets:          []string{"target"},
		RuleResults: map[string]XCCDFRuleResult{
			"rule": {Identity: "rule", Status: ResultPass},
		},
	}
	newResults := &XCCDFResultSet{
		SourcePath:       "new.xml",
		BenchmarkID:      "bench",
		BenchmarkVersion: "1",
		TestResultID:     "new",
		ProfileID:        "profile",
		Targets:          []string{"target"},
		RuleResults: map[string]XCCDFRuleResult{
			"rule": {Identity: "rule", Status: ResultPass},
		},
	}
	comparison, err := CompareXCCDFResults(base, newResults)
	require.NoError(t, err)

	const expected = `XCCDF Result Comparison

Base results: base.xml
  benchmark: bench
  benchmark version: 1
  test result: old
  profile: profile
  targets: target
  start: -
  end: -

New results: new.xml
  benchmark: bench
  benchmark version: 1
  test result: new
  profile: profile
  targets: target
  start: -
  end: -

Base summary: 1 total rule-result(s), 1 in profile scope
  pass: 1
  fail: 0
  error: 0
  unknown: 0
  notapplicable: 0
  notchecked: 0
  notselected: 0
  informational: 0
  fixed: 0

New summary: 1 total rule-result(s), 1 in profile scope
  pass: 1
  fail: 0
  error: 0
  unknown: 0
  notapplicable: 0
  notchecked: 0
  notselected: 0
  informational: 0
  fixed: 0

Comparison summary:
  unchanged:         1
  regressions:       0
  improvements:      0
  reclassifications: 0
  changed:           0

PASS: no XCCDF regressions detected.
`
	require.Equal(t, expected, RenderXCCDFComparison(comparison))
}

func TestLoadXCCDFResults_UsesProfileIDRef(t *testing.T) {
	content := `<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="benchmark"><version>1</version><TestResult id="run"><profile idref=" profile-a "/><target>target</target><rule-result idref="rule"><result>pass</result></rule-result></TestResult></Benchmark>`
	set, err := LoadXCCDFResults(writeResultFixture(t, content))
	require.NoError(t, err)
	require.Equal(t, "profile-a", set.ProfileID)

	candidate, err := LoadXCCDFResults(writeResultFixture(t, strings.Replace(content, "profile-a", "profile-b", 1)))
	require.NoError(t, err)
	_, err = CompareXCCDFResults(set, candidate)
	require.Error(t, err)
}

func TestLoadXCCDFResults_RejectsForeignMetadataNamespaces(t *testing.T) {
	tests := []string{
		`<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:foreign="urn:foreign" id="benchmark"><foreign:version>1</foreign:version><TestResult id="run"><target>target</target><rule-result idref="rule"><result>pass</result></rule-result></TestResult></Benchmark>`,
		`<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:foreign="urn:foreign" id="benchmark"><version>1</version><TestResult id="run"><foreign:target>target</foreign:target><rule-result idref="rule"><result>pass</result></rule-result></TestResult></Benchmark>`,
	}
	for _, content := range tests {
		_, err := LoadXCCDFResults(writeResultFixture(t, content))
		require.Error(t, err)
	}
}

func TestCanonicalInstanceUsesUndefinedDefaultContext(t *testing.T) {
	implicit := canonicalInstance([]xccdfInstance{{Text: "component"}})
	explicit := canonicalInstance([]xccdfInstance{{Text: "component", Context: "undefined"}})
	require.Equal(t, explicit, implicit)
}

func TestRenderXCCDFComparison_SortsChangedRules(t *testing.T) {
	base := &XCCDFResultSet{
		RuleResults: map[string]XCCDFRuleResult{
			"rule-z": {Identity: "rule-z", Status: ResultPass},
			"rule-a": {Identity: "rule-a", Status: ResultPass},
		},
	}
	newResults := &XCCDFResultSet{
		RuleResults: map[string]XCCDFRuleResult{
			"rule-z": {Identity: "rule-z", Status: ResultFail},
			"rule-a": {Identity: "rule-a", Status: ResultFail},
		},
	}
	comparison, err := CompareXCCDFResults(base, newResults)
	require.NoError(t, err)
	require.Contains(t, RenderXCCDFComparison(comparison), "REGRESSIONS (2):\n  rule-a\n    base=pass  new=fail\n  rule-z\n    base=pass  new=fail")
}
