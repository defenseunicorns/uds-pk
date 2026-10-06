// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func enrichmentFixture(name string) string {
	return filepath.Join("..", "test", "stig", name)
}

const testAppName = "siemens-license-server"
const testScanProfile = "xccdf_org.ssgproject.content_profile_stig"

// Start with the real scan's reduced results; each requested status is a test-only variation.
func scanResultsWithStatuses(t *testing.T, statuses map[string]string) string {
	t.Helper()
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-results.xml"))
	require.NoError(t, err)
	for rule, status := range statuses {
		original := `<rule-result idref="xccdf_org.ssgproject.content_rule_` + rule + `"><result>notapplicable</result></rule-result>`
		require.Contains(t, string(data), original)
		changed := `<rule-result idref="xccdf_org.ssgproject.content_rule_` + rule + `"><result>` + status + `</result></rule-result>`
		data = []byte(strings.Replace(string(data), original, changed, 1))
	}
	path := filepath.Join(t.TempDir(), "altered-results.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	return path
}

func TestLoadScanEvidenceMapsRealSSGReferences(t *testing.T) {
	evidence, err := LoadScanEvidence(
		enrichmentFixture("test-rhel9-ssg-results.xml"),
		enrichmentFixture("test-rhel9-ssg-ds.xml"),
	)
	require.NoError(t, err)
	require.Len(t, evidence.ResultsFor("RHEL-09-651010"), 2)
	require.Len(t, evidence.ResultsFor("RHEL-09-291010"), 1)
	require.Empty(t, evidence.ResultsFor("RHEL-09-999999"))
	require.Contains(t, evidence.FindingDetailsFor("RHEL-09-651010", "scan result"), "xccdf_org.ssgproject.content_rule_aide_build_database: notapplicable")
	require.Contains(t, evidence.FindingDetailsFor("RHEL-09-651010", "scan result"), "xccdf_org.ssgproject.content_rule_package_aide_installed: notapplicable")
	status, ok, reason := evidence.DispositionFor("RHEL-09-651010", "SV-258134r1155620_rule")
	require.True(t, ok, reason)
	require.Equal(t, "not_applicable", status)
}

func TestScanDispositionRejectsAmbiguousDISAReferences(t *testing.T) {
	for _, test := range []struct {
		name, extraReference string
	}{
		{name: "another rule version", extraReference: "RHEL-09-291010"},
		{name: "another rule revision", extraReference: "SV-258034r1106302_rule"},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence, err := LoadScanEvidence(
				enrichmentFixture("test-rhel9-ssg-results.xml"),
				enrichmentFixture("test-rhel9-ssg-ds.xml"),
			)
			require.NoError(t, err)
			const ruleID = "xccdf_org.ssgproject.content_rule_package_aide_installed"
			evidence.ruleReferences[ruleID] = append(evidence.ruleReferences[ruleID], test.extraReference)
			_, ok, reason := evidence.DispositionFor("RHEL-09-651010", "SV-258134r1155620_rule")
			require.False(t, ok)
			require.Equal(t, "mapped SSG rule has ambiguous DISA references", reason)
		})
	}
}

func TestLoadScanEvidenceRequiresResultProfile(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-results.xml"))
	require.NoError(t, err)
	data = []byte(strings.Replace(string(data), `<profile idref="`+testScanProfile+`"/>`, "", 1))
	path := filepath.Join(t.TempDir(), "missing-profile.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, err = LoadScanEvidence(path, enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.ErrorContains(t, err, "results must identify the selected scan profile")
}

func TestLoadScanEvidenceDeduplicatesSTIGReferences(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	data = []byte(strings.Replace(string(data), "RHEL-09-291010</reference>", "RHEL-09-291010,RHEL-09-291010</reference>", 1))
	path := filepath.Join(t.TempDir(), "duplicate-reference.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	evidence, err := LoadScanEvidence(enrichmentFixture("test-rhel9-ssg-results.xml"), path)
	require.NoError(t, err)
	require.Len(t, evidence.ResultsFor("RHEL-09-291010"), 1)
}

func TestScanDispositionRequiresAgreementAndEvaluatedStatus(t *testing.T) {
	tests := []struct {
		name    string
		results []XCCDFRuleResult
		want    string
		ok      bool
	}{
		{name: "pass", results: []XCCDFRuleResult{{Status: ResultPass}}, want: "not_a_finding", ok: true},
		{name: "fail", results: []XCCDFRuleResult{{Status: ResultFail}}, want: "open", ok: true},
		{name: "not applicable", results: []XCCDFRuleResult{{Status: ResultNotApplicable}}, want: "not_applicable", ok: true},
		{name: "agreeing results", results: []XCCDFRuleResult{{Status: ResultPass}, {Status: ResultPass}}, want: "not_a_finding", ok: true},
		{name: "conflicting results", results: []XCCDFRuleResult{{Status: ResultPass}, {Status: ResultFail}}},
		{name: "scan error", results: []XCCDFRuleResult{{Status: ResultError}}},
		{name: "fixed without rescan", results: []XCCDFRuleResult{{Status: ResultFixed}}},
		{name: "no result"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := ScanDisposition(test.results)
			require.Equal(t, test.want, got)
			require.Equal(t, test.ok, ok)
		})
	}
}

func TestParseXCCDFWithEvidenceHonorsPrecedence(t *testing.T) {
	// The real scan reports notapplicable for these rules. Alter statuses only
	// for the conflict, scan-overrides-heuristic, and human-override scenarios.
	resultsPath := scanResultsWithStatuses(t, map[string]string{
		"package_aide_installed":             "pass",
		"aide_build_database":                "fail",
		"kernel_module_usb-storage_disabled": "fail",
		"aide_check_audit_tools":             "pass",
	})
	evidence, err := LoadScanEvidence(
		resultsPath,
		enrichmentFixture("test-rhel9-ssg-ds.xml"),
	)
	require.NoError(t, err)
	profile := &Profile{
		AppName:      testAppName,
		SelectedSTIG: &STIGProfile{ID: RHEL9STIGProfileKey},
		Chars:        Characteristics{USBStorageDisabled: true},
	}
	stig, err := ParseXCCDFWithEvidence(enrichmentFixture("test-rhel9-enrichment-xccdf.xml"), profile, evidence)
	require.NoError(t, err)
	rules := make(map[string]Rule, len(stig.Rules))
	for _, rule := range stig.Rules {
		rules[rule.RuleVersion] = rule
	}
	require.Equal(t, "not_reviewed", rules["RHEL-09-651010"].Status) // conflicting scan falls back to heuristic
	require.Contains(t, rules["RHEL-09-651010"].FindingDetails, "package_aide_installed: pass")
	require.Contains(t, rules["RHEL-09-651010"].FindingDetails, "aide_build_database: fail")
	require.Contains(t, rules["RHEL-09-651010"].FindingDetails, "scan not used: mapped scan results conflict")
	require.Equal(t, "open", rules["RHEL-09-291010"].Status) // scan overrides USB-disabled heuristic
	require.Contains(t, rules["RHEL-09-291010"].FindingDetails, "kernel_module_usb-storage_disabled: fail")
	require.Contains(t, rules["RHEL-09-291010"].FindingDetails, "Disposition source: scan result")
	require.NotContains(t, rules["RHEL-09-291010"].FindingDetails, "does not permit removable media")
	require.Equal(t, "not_a_finding", rules["RHEL-09-651025"].Status)
	require.Equal(t, "not_reviewed", rules["RHEL-09-999999"].Status)
	require.NotContains(t, rules["RHEL-09-999999"].FindingDetails, "OpenSCAP results:")

	profile.Overrides = map[string]Override{
		"RHEL-09-291010": {
			Status:         "not_applicable",
			FindingDetails: "Approved human exception.",
			Comments:       "Reviewed by operator.",
		},
	}
	stig, err = ParseXCCDFWithEvidence(enrichmentFixture("test-rhel9-enrichment-xccdf.xml"), profile, evidence)
	require.NoError(t, err)
	require.Equal(t, "not_applicable", stig.Rules[1].Status)
	require.Contains(t, stig.Rules[1].FindingDetails, "Approved human exception.")
	require.Contains(t, stig.Rules[1].FindingDetails, "kernel_module_usb-storage_disabled: fail")
	require.Contains(t, stig.Rules[1].FindingDetails, "Disposition source: human profile override")
	require.Equal(t, "Reviewed by operator.", stig.Rules[1].Comments)
}

func TestParseXCCDFWithEvidenceRejectsChangedDISARuleRevision(t *testing.T) {
	resultsPath := scanResultsWithStatuses(t, map[string]string{
		"package_aide_installed": "pass",
		"aide_build_database":    "pass",
	})
	evidence, err := LoadScanEvidence(resultsPath, enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-enrichment-xccdf.xml"))
	require.NoError(t, err)
	const original = `id="SV-258134r1155620_rule"`
	require.Contains(t, string(data), original)
	data = []byte(strings.Replace(string(data), original, `id="SV-258134r9999999_rule"`, 1))
	path := filepath.Join(t.TempDir(), "changed-disa-revision.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	profile := &Profile{SelectedSTIG: &STIGProfile{ID: RHEL9STIGProfileKey}}
	stig, err := ParseXCCDFWithEvidence(path, profile, evidence)
	require.NoError(t, err)
	require.Equal(t, "not_reviewed", stig.Rules[0].Status)
	require.Contains(t, stig.Rules[0].FindingDetails, "mapped SSG rule revision does not match the DISA rule")
	require.Contains(t, stig.Rules[0].FindingDetails, "package_aide_installed: pass")
}

func TestLoadScanEvidenceRejectsMismatchedDataStream(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	data = []byte(strings.Replace(string(data), "content_benchmark_RHEL-9", "content_benchmark_RHEL-8", 1))
	path := filepath.Join(t.TempDir(), "wrong-ds.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, err = LoadScanEvidence(enrichmentFixture("test-rhel9-ssg-results.xml"), path)
	require.ErrorContains(t, err, "not found in data stream")
}

func TestLoadScanEvidenceRejectsUnlinkedDataStreamBenchmark(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	const original = `xlink:href="#scap_test_comp_rhel9"`
	require.Contains(t, string(data), original)
	data = []byte(strings.Replace(string(data), original, `xlink:href="#unrelated_component"`, 1))
	path := filepath.Join(t.TempDir(), "unlinked-ds.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, err = LoadScanEvidence(enrichmentFixture("test-rhel9-ssg-results.xml"), path)
	require.ErrorContains(t, err, "not found in data stream")
}

func TestLoadScanEvidenceRequiresProfileInDataStream(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	const original = `<Profile id="xccdf_org.ssgproject.content_profile_stig">`
	require.Contains(t, string(data), original)
	data = []byte(strings.Replace(string(data), original, `<Profile id="another-profile">`, 1))
	path := filepath.Join(t.TempDir(), "wrong-profile-ds.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, err = LoadScanEvidence(enrichmentFixture("test-rhel9-ssg-results.xml"), path)
	require.ErrorContains(t, err, "profile \""+testScanProfile+"\" not found in data stream")
}

func TestLoadScanEvidenceRejectsDifferentProfileSelections(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	const original = `<Profile id="xccdf_org.ssgproject.content_profile_stig"><title>DISA STIG for Red Hat Enterprise Linux 9</title></Profile>`
	require.Contains(t, string(data), original)
	changed := `<Profile id="xccdf_org.ssgproject.content_profile_stig"><title>DISA STIG for Red Hat Enterprise Linux 9</title><select idref="xccdf_org.ssgproject.content_rule_package_aide_installed" selected="false"/></Profile>`
	path := filepath.Join(t.TempDir(), "different-profile-ds.xml")
	require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(data), original, changed, 1)), 0o644))
	_, err = LoadScanEvidence(enrichmentFixture("test-rhel9-ssg-results.xml"), path)
	require.ErrorContains(t, err, "does not match the data stream profile")
}

func TestLoadScanEvidenceRejectsChangedDataStreamReferences(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	const original = `RHEL-09-291010</reference>`
	require.Contains(t, string(data), original)
	data = []byte(strings.Replace(string(data), original, `RHEL-09-000000</reference>`, 1))
	path := filepath.Join(t.TempDir(), "changed-refs-ds.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, err = LoadScanEvidence(enrichmentFixture("test-rhel9-ssg-results.xml"), path)
	require.ErrorContains(t, err, "STIG references that do not match")
}

func TestLoadScanEvidenceRejectsVersionMismatch(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	require.Contains(t, string(data), "0.1.82</version>")
	data = []byte(strings.Replace(string(data), "0.1.82</version>", "0.1.81</version>", 1))
	path := filepath.Join(t.TempDir(), "old-ds.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, err = LoadScanEvidence(enrichmentFixture("test-rhel9-ssg-results.xml"), path)
	require.ErrorContains(t, err, "does not match data stream version")
}

func TestLoadScanEvidenceRequiresBenchmarkVersions(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-results.xml"))
	require.NoError(t, err)
	version := `<version update="https://github.com/ComplianceAsCode/content/releases/latest">0.1.82</version>`
	require.Contains(t, string(data), version)
	data = []byte(strings.Replace(string(data), version, "", 1))
	path := filepath.Join(t.TempDir(), "unversioned-results.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, err = LoadScanEvidence(path, enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.ErrorContains(t, err, "must both contain a benchmark version")
}

func TestScanDispositionWaitsForEveryMappedRule(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-results.xml"))
	require.NoError(t, err)
	data = []byte(strings.Replace(string(data), `<rule-result idref="xccdf_org.ssgproject.content_rule_aide_build_database"><result>notapplicable</result></rule-result>`, "", 1))
	path := filepath.Join(t.TempDir(), "partial-results.xml")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	evidence, err := LoadScanEvidence(path, enrichmentFixture("test-rhel9-ssg-ds.xml"))
	require.NoError(t, err)
	require.Len(t, evidence.ResultsFor("RHEL-09-651010"), 1)
	_, ok, reason := evidence.DispositionFor("RHEL-09-651010", "SV-258134r1155620_rule")
	require.False(t, ok)
	require.Contains(t, reason, "missing")
	profile := &Profile{SelectedSTIG: &STIGProfile{ID: RHEL9STIGProfileKey}}
	stig, err := ParseXCCDFWithEvidence(enrichmentFixture("test-rhel9-enrichment-xccdf.xml"), profile, evidence)
	require.NoError(t, err)
	require.Contains(t, stig.Rules[0].FindingDetails, "scan not used: results are missing")
}

func TestParseXCCDFWithEvidenceHandlesOtherScanStatuses(t *testing.T) {
	data, err := os.ReadFile(enrichmentFixture("test-rhel9-ssg-results.xml"))
	require.NoError(t, err)
	profile := &Profile{
		AppName:      testAppName,
		SelectedSTIG: &STIGProfile{ID: RHEL9STIGProfileKey},
		Chars:        Characteristics{USBStorageDisabled: true},
	}
	for _, test := range []struct {
		name, scanStatus, wantStatus string
	}{
		{name: "not applicable", scanStatus: "notapplicable", wantStatus: "not_applicable"},
		{name: "error falls back to heuristic", scanStatus: "error", wantStatus: "not_applicable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := strings.Replace(string(data), `content_rule_kernel_module_usb-storage_disabled"><result>notapplicable`, `content_rule_kernel_module_usb-storage_disabled"><result>`+test.scanStatus, 1)
			path := filepath.Join(t.TempDir(), "results.xml")
			require.NoError(t, os.WriteFile(path, []byte(changed), 0o644))
			evidence, err := LoadScanEvidence(path, enrichmentFixture("test-rhel9-ssg-ds.xml"))
			require.NoError(t, err)
			stig, err := ParseXCCDFWithEvidence(enrichmentFixture("test-rhel9-enrichment-xccdf.xml"), profile, evidence)
			require.NoError(t, err)
			require.Equal(t, test.wantStatus, stig.Rules[1].Status)
			require.Contains(t, stig.Rules[1].FindingDetails, "kernel_module_usb-storage_disabled: "+test.scanStatus)
			require.Contains(t, stig.Rules[1].FindingDetails, "does not permit removable media in normal operation")
		})
	}
}
