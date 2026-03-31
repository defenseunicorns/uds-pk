// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStigGenerateChecklist(t *testing.T) {
	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "output.cklb")

	stdout, stderr, err := e2e.UDSPK("stig", "generate-checklist",
		"--profile", "src/test/stig/test-profile.yaml",
		"--xccdf", "src/test/stig/test-xccdf.xml",
		"--output", outputPath,
	)
	require.NoError(t, err, stdout, stderr)

	// Verify summary output
	assert.Contains(t, stdout, "Generated "+outputPath)
	assert.Contains(t, stdout, "Total rules: 5")
	assert.Contains(t, stdout, "not_a_finding:")
	assert.Contains(t, stdout, "not_applicable:")

	// Verify output file exists and is valid JSON
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var checklist map[string]interface{}
	err = json.Unmarshal(data, &checklist)
	require.NoError(t, err)

	// Verify top-level checklist fields
	assert.Equal(t, "e2e-test-app-asd-v6r4", checklist["title"])
	assert.Equal(t, "1.0", checklist["cklb_version"])
	assert.Equal(t, false, checklist["active"])
	assert.Equal(t, float64(1), checklist["mode"])
	assert.Equal(t, true, checklist["has_path"])
	assert.NotEmpty(t, checklist["id"])

	// Verify target_data
	targetData, ok := checklist["target_data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "e2e-test-app", targetData["host_name"])
	assert.Equal(t, "e2e.example.com", targetData["fqdn"])
	assert.Equal(t, "Computing", targetData["target_type"])
	assert.Equal(t, "Application Server", targetData["role"])
	assert.Equal(t, "Application Review", targetData["technology_area"])

	// Verify stigs array
	stigs, ok := checklist["stigs"].([]interface{})
	require.True(t, ok)
	require.Len(t, stigs, 1)

	stig, ok := stigs[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Application Security and Development Security Technical Implementation Guide", stig["stig_name"])
	assert.Equal(t, "Application_Security_Development_STIG", stig["stig_id"])
	assert.Equal(t, "Release: 1 Benchmark Date: 01 Jan 2025", stig["release_info"])
	assert.Equal(t, float64(5), stig["size"])

	// Verify rules
	rules, ok := stig["rules"].([]interface{})
	require.True(t, ok)
	require.Len(t, rules, 5)
}

func TestStigGenerateChecklistRuleStatuses(t *testing.T) {
	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "statuses.cklb")

	stdout, stderr, err := e2e.UDSPK("stig", "generate-checklist",
		"--profile", "src/test/stig/test-profile.yaml",
		"--xccdf", "src/test/stig/test-xccdf.xml",
		"--output", outputPath,
	)
	require.NoError(t, err, stdout, stderr)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var checklist map[string]interface{}
	err = json.Unmarshal(data, &checklist)
	require.NoError(t, err)

	stigs := checklist["stigs"].([]interface{})
	stig := stigs[0].(map[string]interface{})
	rules := stig["rules"].([]interface{})

	// Build a map of rule_version -> status for easy assertion
	statusByVersion := map[string]string{}
	for _, r := range rules {
		rule := r.(map[string]interface{})
		statusByVersion[rule["rule_version"].(string)] = rule["status"].(string)
	}

	// APSC-DV-000160 (TLS/encryption with service mesh) → not_a_finding
	assert.Equal(t, "not_a_finding", statusByVersion["APSC-DV-000160"])
	// APSC-DV-002010 (SOAP not used) → not_applicable
	assert.Equal(t, "not_applicable", statusByVersion["APSC-DV-002010"])
	// APSC-DV-001680 (passwords not used) → not_applicable
	assert.Equal(t, "not_applicable", statusByVersion["APSC-DV-001680"])
	// APSC-DV-002900 (audit retention) → not_reviewed
	assert.Equal(t, "not_reviewed", statusByVersion["APSC-DV-002900"])
	// APSC-DV-000010 (session limiting with auth) → not_a_finding
	assert.Equal(t, "not_a_finding", statusByVersion["APSC-DV-000010"])
}

func TestStigGenerateChecklistRuleFields(t *testing.T) {
	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "fields.cklb")

	stdout, stderr, err := e2e.UDSPK("stig", "generate-checklist",
		"--profile", "src/test/stig/test-profile.yaml",
		"--xccdf", "src/test/stig/test-xccdf.xml",
		"--output", outputPath,
	)
	require.NoError(t, err, stdout, stderr)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var checklist map[string]interface{}
	err = json.Unmarshal(data, &checklist)
	require.NoError(t, err)

	stigs := checklist["stigs"].([]interface{})
	stig := stigs[0].(map[string]interface{})
	rules := stig["rules"].([]interface{})

	// Check detailed fields on the first rule (APSC-DV-000160)
	rule := rules[0].(map[string]interface{})
	assert.Equal(t, "V-222400", rule["group_id_src"])
	assert.Equal(t, "V-222400", rule["group_id"])
	assert.Equal(t, "high", rule["severity"])
	assert.Equal(t, "10.0", rule["weight"])
	assert.Equal(t, "APSC-DV-000160", rule["rule_version"])
	assert.Equal(t, "SV-222400r1_rule", rule["rule_id_src"])
	assert.Equal(t, "SV-222400r1", rule["rule_id"])
	assert.Equal(t, "Unclassified", rule["classification"])
	assert.Equal(t, "false", rule["documentable"])
	assert.NotEmpty(t, rule["uuid"])
	assert.NotEmpty(t, rule["stig_uuid"])
	assert.NotEmpty(t, rule["fix_text"])
	assert.NotEmpty(t, rule["check_content"])
	assert.NotEmpty(t, rule["discussion"])
	assert.NotEmpty(t, rule["finding_details"])

	// Verify check_content_ref
	ref, ok := rule["check_content_ref"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Application_Security_and_Development_STIG.xml", ref["href"])
	assert.Equal(t, "M", ref["name"])

	// Verify group_tree
	groupTree, ok := rule["group_tree"].([]interface{})
	require.True(t, ok)
	require.Len(t, groupTree, 1)
	entry := groupTree[0].(map[string]interface{})
	assert.Equal(t, "V-222400", entry["id"])
	assert.Equal(t, "SRG-APP-000014", entry["title"])

	// Verify idents
	ccis, ok := rule["ccis"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, ccis, "CCI-000068")

	legacyIDs, ok := rule["legacy_ids"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, legacyIDs, "V-69289")
	assert.Contains(t, legacyIDs, "SV-83911")

	// Verify reference_identifier
	assert.Equal(t, "4093", rule["reference_identifier"])
}

func TestStigGenerateChecklistDefaultOutput(t *testing.T) {
	// When --output is not specified, default is <app_name>-asd-v6r4.cklb
	stdout, stderr, err := e2e.UDSPK("stig", "generate-checklist",
		"--profile", "src/test/stig/test-profile.yaml",
		"--xccdf", "src/test/stig/test-xccdf.xml",
	)
	require.NoError(t, err, stdout, stderr)

	defaultOutput := "e2e-test-app-asd-v6r4.cklb"
	defer e2e.CleanFiles(defaultOutput)

	assert.Contains(t, stdout, "Generated "+defaultOutput)

	_, err = os.Stat(defaultOutput)
	require.NoError(t, err, "default output file should exist")
}

func TestStigGenerateChecklistMissingXCCDF(t *testing.T) {
	_, _, err := e2e.UDSPK("stig", "generate-checklist",
		"--profile", "src/test/stig/test-profile.yaml",
	)
	require.Error(t, err)
}

func TestStigGenerateChecklistInvalidProfile(t *testing.T) {
	_, stderr, err := e2e.UDSPK("stig", "generate-checklist",
		"--profile", "nonexistent-profile.yaml",
		"--xccdf", "src/test/stig/test-xccdf.xml",
	)
	require.Error(t, err)
	assert.Contains(t, stderr, "failed to load profile")
}

func TestStigGenerateChecklistInvalidXCCDF(t *testing.T) {
	_, stderr, err := e2e.UDSPK("stig", "generate-checklist",
		"--profile", "src/test/stig/test-profile.yaml",
		"--xccdf", "nonexistent-xccdf.xml",
	)
	require.Error(t, err)
	assert.Contains(t, stderr, "failed to parse XCCDF")
}

func TestStigGenerateChecklistWithRealSTIG(t *testing.T) {
	// Test with the full ASD V6R4 STIG from port/ directory
	xccdfPath := "port/stig/U_ASD_V6R4_STIG/U_ASD_V6R4_Manual_STIG/U_ASD_STIG_V6R4_Manual-xccdf.xml"
	if _, err := os.Stat(xccdfPath); os.IsNotExist(err) {
		t.Skip("Full STIG XCCDF not available, skipping")
	}

	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "full-stig.cklb")

	stdout, stderr, err := e2e.UDSPK("stig", "generate-checklist",
		"--profile", "port/stig-profile.yaml",
		"--xccdf", xccdfPath,
		"--output", outputPath,
	)
	require.NoError(t, err, stdout, stderr)

	assert.Contains(t, stdout, "Total rules: 286")

	// Verify the output is valid JSON
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var checklist map[string]interface{}
	err = json.Unmarshal(data, &checklist)
	require.NoError(t, err)

	stigs := checklist["stigs"].([]interface{})
	stig := stigs[0].(map[string]interface{})
	assert.Equal(t, float64(286), stig["size"])
}
