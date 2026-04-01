// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var testProfile = &Profile{
	AppName:     "test-app",
	FQDN:        "test.example.com",
	Description: "Test application.",
	Chars: Characteristics{
		IsStateless:  true,
		HasUserInput: false,
		Language:     "go",
	},
	Platform: PlatformConfig{
		AuthProvider:      "Keycloak",
		AuthProxy:         "authservice",
		ServiceMesh:       "Istio",
		ContainerRuntime:  "Kubernetes",
		ContainerUser:     "nonroot",
		BaseImage:         "golang:1.22-alpine",
		NetworkPolicies:   true,
		CICD_SAST:         "Semgrep",
		CICD_SecretsScan:  "Gitleaks",
		CICD_Signing:      "Cosign",
		DependencyMonitor: "Renovate",
		SCM:               "GitHub",
		DefectTracking:    "GitHub Issues",
		ResourceLimits:    "CPU: 200m",
	},
}

const minimalXCCDF = `<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"
           xmlns:dc="http://purl.org/dc/elements/1.1/"
           id="Test_STIG" xml:lang="en">
  <status date="2025-01-01">accepted</status>
  <title>Test STIG</title>
  <version>1</version>
  <plain-text id="release-info">Release: 1 Benchmark Date: 01 Jan 2025</plain-text>
  <Group id="V-100001">
    <title>SRG-APP-000001</title>
    <description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>
    <Rule id="SV-100001r1_rule" severity="medium" weight="10.0">
      <version>APSC-DV-000160</version>
      <title>The application must implement DoD-approved encryption.</title>
      <description>&lt;VulnDiscussion&gt;Encryption protects data.&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;FalseNegatives&gt;&lt;/FalseNegatives&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;&lt;SeverityOverrideGuidance&gt;&lt;/SeverityOverrideGuidance&gt;&lt;PotentialImpacts&gt;&lt;/PotentialImpacts&gt;&lt;ThirdPartyTools&gt;&lt;/ThirdPartyTools&gt;&lt;IAControls&gt;&lt;/IAControls&gt;&lt;Responsibility&gt;&lt;/Responsibility&gt;&lt;Mitigations&gt;&lt;/Mitigations&gt;&lt;MitigationControl&gt;&lt;/MitigationControl&gt;</description>
      <reference>
        <dc:identifier>4093</dc:identifier>
      </reference>
      <ident system="http://cyber.mil/cci">CCI-000068</ident>
      <ident system="http://cyber.mil/legacy">V-12345</ident>
      <fixtext>Configure encryption.</fixtext>
      <check>
        <check-content-ref href="Test_STIG.xml" name="M" />
        <check-content>Verify encryption is enabled.</check-content>
      </check>
    </Rule>
  </Group>
  <Group id="V-100002">
    <title>SRG-APP-000002</title>
    <description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>
    <Rule id="SV-100002r1_rule" severity="high" weight="10.0">
      <version>APSC-DV-002900</version>
      <title>The application must retain audit records.</title>
      <description>&lt;VulnDiscussion&gt;Audit retention is important.&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;FalseNegatives&gt;&lt;/FalseNegatives&gt;&lt;Documentable&gt;true&lt;/Documentable&gt;&lt;SeverityOverrideGuidance&gt;&lt;/SeverityOverrideGuidance&gt;&lt;PotentialImpacts&gt;&lt;/PotentialImpacts&gt;&lt;ThirdPartyTools&gt;&lt;/ThirdPartyTools&gt;&lt;IAControls&gt;&lt;/IAControls&gt;&lt;Responsibility&gt;&lt;/Responsibility&gt;&lt;Mitigations&gt;&lt;/Mitigations&gt;&lt;MitigationControl&gt;&lt;/MitigationControl&gt;</description>
      <reference>
        <dc:identifier>4093</dc:identifier>
      </reference>
      <ident system="http://cyber.mil/cci">CCI-001849</ident>
      <fixtext>Configure audit retention.</fixtext>
      <check>
        <check-content-ref href="Test_STIG.xml" name="M" />
        <check-content>Verify audit retention is configured.</check-content>
      </check>
    </Rule>
  </Group>
</Benchmark>`

func writeXCCDFFixture(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test-xccdf.xml")
	err := os.WriteFile(path, []byte(minimalXCCDF), 0644)
	require.NoError(t, err)
	return path
}

func TestParseXCCDF_Success(t *testing.T) {
	dir := t.TempDir()
	xccdfPath := writeXCCDFFixture(t, dir)

	s, err := ParseXCCDF(xccdfPath, testProfile)
	require.NoError(t, err)

	require.Equal(t, "Application Security and Development Security Technical Implementation Guide", s.STIGName)
	require.Equal(t, "Application_Security_Development_STIG", s.STIGID)
	require.Equal(t, "Release: 1 Benchmark Date: 01 Jan 2025", s.ReleaseInfo)
	require.NotEmpty(t, s.UUID)
	require.Equal(t, 2, s.Size)
	require.Len(t, s.Rules, 2)

	// Reference identifier from first rule
	require.NotNil(t, s.ReferenceIdentifier)
	require.Equal(t, "4093", *s.ReferenceIdentifier)
}

func TestParseXCCDF_RuleFields(t *testing.T) {
	dir := t.TempDir()
	xccdfPath := writeXCCDFFixture(t, dir)

	s, err := ParseXCCDF(xccdfPath, testProfile)
	require.NoError(t, err)

	r := s.Rules[0]
	require.Equal(t, "V-100001", r.GroupIDSrc)
	require.Equal(t, "V-100001", r.GroupID)
	require.Equal(t, "medium", r.Severity)
	require.Equal(t, "10.0", r.Weight)
	require.Equal(t, "APSC-DV-000160", r.RuleVersion)
	require.Equal(t, "The application must implement DoD-approved encryption.", r.RuleTitle)
	require.Equal(t, r.RuleTitle, r.GroupTitle)
	require.Equal(t, "Configure encryption.", r.FixText)
	require.Equal(t, "Verify encryption is enabled.", r.CheckContent)
	require.Equal(t, "Unclassified", r.Classification)
	require.Equal(t, "Encryption protects data.", r.Discussion)
	require.Equal(t, "false", r.Documentable)
	require.NotEmpty(t, r.UUID)
	require.Equal(t, s.UUID, r.SIGUUID)

	// Check content ref
	require.NotNil(t, r.CheckContentRef)
	require.Equal(t, "Test_STIG.xml", r.CheckContentRef.Href)
	require.Equal(t, "M", r.CheckContentRef.Name)

	// Group tree
	require.Len(t, r.GroupTree, 1)
	require.Equal(t, "V-100001", r.GroupTree[0].ID)
	require.Equal(t, "SRG-APP-000001", r.GroupTree[0].Title)

	// Idents
	require.Equal(t, []string{"CCI-000068"}, r.CCIs)
	require.Equal(t, []string{"V-12345"}, r.LegacyIDs)

	// Reference identifier
	require.NotNil(t, r.ReferenceID)
	require.Equal(t, "4093", *r.ReferenceID)

	// Rule ID pretty-printing (strips _rule suffix)
	require.Equal(t, "SV-100001r1_rule", r.RuleIDSrc)
	require.Equal(t, "SV-100001r1", r.RuleID)
}

func TestParseXCCDF_EvaluatesRules(t *testing.T) {
	dir := t.TempDir()
	xccdfPath := writeXCCDFFixture(t, dir)

	s, err := ParseXCCDF(xccdfPath, testProfile)
	require.NoError(t, err)

	// APSC-DV-000160 with service mesh should be not_a_finding
	require.Equal(t, "not_a_finding", s.Rules[0].Status)
	require.NotEmpty(t, s.Rules[0].FindingDetails)

	// APSC-DV-002900 is in the not_reviewed map
	require.Equal(t, "not_reviewed", s.Rules[1].Status)
}

func TestParseXCCDF_AppliesOverrides(t *testing.T) {
	dir := t.TempDir()
	xccdfPath := writeXCCDFFixture(t, dir)

	profileWithOverrides := &Profile{
		AppName:     "override-app",
		FQDN:        "override.example.com",
		Description: "App with overrides.",
		Chars:       testProfile.Chars,
		Platform:    testProfile.Platform,
		Overrides: map[string]Override{
			"APSC-DV-000160": {
				Status:         "not_applicable",
				FindingDetails: "Overridden finding.",
				Comments:       "Override comment.",
			},
		},
	}

	s, err := ParseXCCDF(xccdfPath, profileWithOverrides)
	require.NoError(t, err)

	r := s.Rules[0]
	require.Equal(t, "not_applicable", r.Status)
	require.Equal(t, "Overridden finding.", r.FindingDetails)
	require.Equal(t, "Override comment.", r.Comments)
}

func TestParseXCCDF_FileNotFound(t *testing.T) {
	_, err := ParseXCCDF("/nonexistent/file.xml", testProfile)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reading")
}

func TestParseXCCDF_InvalidXML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.xml")
	err := os.WriteFile(path, []byte("not xml at all"), 0644)
	require.NoError(t, err)

	_, err = ParseXCCDF(path, testProfile)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing XCCDF")
}

func TestBuildChecklist(t *testing.T) {
	s := &STIG{
		STIGName: "Test STIG",
		STIGID:   "Test_STIG",
		UUID:     "stig-uuid",
		Size:     1,
		Rules: []Rule{
			{GroupIDSrc: "V-100001", Status: "not_a_finding"},
		},
	}

	checklist := BuildChecklist(testProfile, s)

	handler, err := ResolveFamilyHandler(testProfile)
	require.NoError(t, err)
	meta := handler.Metadata(testProfile, nil)

	require.Equal(t, ChecklistTitle(testProfile, meta), checklist.Title)
	require.NotEmpty(t, checklist.ID)
	require.Equal(t, "1.0", checklist.CKLBVersion)
	require.False(t, checklist.Active)
	require.Equal(t, 1, checklist.Mode)
	require.True(t, checklist.HasPath)

	// Target data
	td := checklist.TargetData
	require.NotNil(t, td)
	require.Equal(t, "Computing", td.TargetType)
	require.Equal(t, "test-app", td.HostName)
	require.Equal(t, "test.example.com", td.FQDN)
	require.Equal(t, "Test application.", td.Comments)
	require.Equal(t, "Application Server", td.Role)
	require.False(t, td.IsWebDatabase)
	require.Equal(t, "Application Review", td.TechnologyArea)

	// STIGs
	require.Len(t, checklist.STIGs, 1)
	require.Equal(t, "Test STIG", checklist.STIGs[0].STIGName)
	require.Len(t, checklist.STIGs[0].Rules, 1)
}

func TestParseXCCDF_RHEL9FamilyUsesBenchmarkMetadata(t *testing.T) {
	dir := t.TempDir()
	xccdfPath := filepath.Join(dir, "rhel9-xccdf.xml")
	xml := `<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG" xml:lang="en">
  <title>Red Hat Enterprise Linux 9 STIG</title>
  <plain-text id="release-info">Release: 7 Benchmark Date: 01 Apr 2026</plain-text>
  <Group id="V-1">
    <title>SRG-OS-000001</title>
    <description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>
    <Rule id="SV-1_rule" severity="medium" weight="10.0">
      <version>RHEL-09-000001</version>
      <title>The graphical user interface must not be installed.</title>
      <description>&lt;VulnDiscussion&gt;GUI increases attack surface.&lt;/VulnDiscussion&gt;</description>
      <fixtext>Remove GUI packages.</fixtext>
      <check>
        <check-content>Verify no GUI packages are installed.</check-content>
      </check>
    </Rule>
  </Group>
</Benchmark>`
	err := os.WriteFile(xccdfPath, []byte(xml), 0644)
	require.NoError(t, err)

	profile := &Profile{
		Family:      FamilyRHEL9,
		AppName:     "rhel9-node01",
		FQDN:        "node01.example.com",
		Description: "Test host.",
		Chars: Characteristics{
			HasGUI: false,
		},
		Platform: PlatformConfig{
			HostRole: "Standalone Kubernetes server",
		},
	}

	s, err := ParseXCCDF(xccdfPath, profile)
	require.NoError(t, err)
	require.Equal(t, "Red Hat Enterprise Linux 9 STIG", s.STIGName)
	require.Equal(t, "RHEL_9_STIG", s.STIGID)
	require.Equal(t, "not_applicable", s.Rules[0].Status)

	checklist := BuildChecklist(profile, s)
	handler, err := ResolveFamilyHandler(profile)
	require.NoError(t, err)
	meta := handler.Metadata(profile, nil)
	require.Equal(t, ChecklistTitle(profile, meta), checklist.Title)
	require.Equal(t, "Standalone Kubernetes server", checklist.TargetData.Role)
	require.Equal(t, "Operating System Review", checklist.TargetData.TechnologyArea)
}

func TestExtractXMLTag(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		tag      string
		expected string
	}{
		{
			name:     "extracts tag content",
			text:     "<VulnDiscussion>This is the discussion.</VulnDiscussion>",
			tag:      "VulnDiscussion",
			expected: "This is the discussion.",
		},
		{
			name:     "trims whitespace",
			text:     "<FalsePositives>  some text  </FalsePositives>",
			tag:      "FalsePositives",
			expected: "some text",
		},
		{
			name:     "empty tag",
			text:     "<FalseNegatives></FalseNegatives>",
			tag:      "FalseNegatives",
			expected: "",
		},
		{
			name:     "tag not found",
			text:     "<VulnDiscussion>Content</VulnDiscussion>",
			tag:      "MissingTag",
			expected: "",
		},
		{
			name:     "extracts from longer text",
			text:     "<VulnDiscussion>Discussion</VulnDiscussion><FalsePositives>FP</FalsePositives><Documentable>true</Documentable>",
			tag:      "Documentable",
			expected: "true",
		},
		{
			name:     "empty input",
			text:     "",
			tag:      "VulnDiscussion",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractXMLTag(tt.text, tt.tag)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseXCCDF_DocumentableField(t *testing.T) {
	dir := t.TempDir()
	xccdfPath := writeXCCDFFixture(t, dir)

	s, err := ParseXCCDF(xccdfPath, testProfile)
	require.NoError(t, err)

	// First rule has Documentable=false
	require.Equal(t, "false", s.Rules[0].Documentable)
	// Second rule has Documentable=true
	require.Equal(t, "true", s.Rules[1].Documentable)
}

func TestParseXCCDF_EmptyNilSlices(t *testing.T) {
	// Rules with no idents should get empty (not nil) slices
	dir := t.TempDir()
	xml := `<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Test_STIG" xml:lang="en">
  <version>1</version>
  <Group id="V-999999">
    <title>SRG-TEST</title>
    <description></description>
    <Rule id="SV-999999r1_rule" severity="low" weight="10.0">
      <version>APSC-DV-999999</version>
      <title>Test rule with no idents.</title>
      <description>&lt;VulnDiscussion&gt;Test.&lt;/VulnDiscussion&gt;</description>
      <fixtext>Fix it.</fixtext>
      <check>
        <check-content>Check it.</check-content>
      </check>
    </Rule>
  </Group>
</Benchmark>`
	path := filepath.Join(dir, "no-idents.xml")
	err := os.WriteFile(path, []byte(xml), 0644)
	require.NoError(t, err)

	s, err := ParseXCCDF(path, testProfile)
	require.NoError(t, err)
	require.Len(t, s.Rules, 1)

	r := s.Rules[0]
	require.NotNil(t, r.CCIs)
	require.Empty(t, r.CCIs)
	require.NotNil(t, r.LegacyIDs)
	require.Empty(t, r.LegacyIDs)
	require.NotNil(t, r.Overrides)
}
