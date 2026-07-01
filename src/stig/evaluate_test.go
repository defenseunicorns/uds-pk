// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var evalProfile = &Profile{
	AppName:     "eval-app",
	FQDN:        "eval.example.com",
	Description: "Evaluation test app.",
	Chars: Characteristics{
		UsesSOAP:             false,
		UsesSAML:             false,
		UsesXML:              false,
		UsesDatabase:         false,
		UsesPasswords:        false,
		UsesPKI:              false,
		ProcessesClassified:  false,
		ProcessesCUI:         false,
		HasUserInput:         false,
		HasAdminInterface:    false,
		HasFileUpload:        false,
		IsStateless:          true,
		HasMobileCode:        false,
		IsPubliclyAccessible: false,
		HasWebServices:       false,
		HasSharedAccounts:    false,
		HasNonLocalMaint:     false,
		DoesKeyExchange:      false,
		IsTransactionBased:   false,
		IsConfigMgmtApp:      false,
		AuthenticatesDevices: false,
		InDoDDMZ:             false,
		IsCritical:           false,
		HostsNonOrgUsers:     false,
		DevelopedInHouse:     true,
		Language:             "python",
	},
	Platform: PlatformConfig{
		AuthProvider:      "Keycloak SSO (OIDC)",
		AuthProxy:         "authservice",
		ServiceMesh:       "Istio ambient",
		ContainerRuntime:  "Kubernetes",
		ContainerUser:     "non-root (appuser)",
		BaseImage:         "python:3.13-alpine",
		NetworkPolicies:   true,
		CICD_SAST:         "OpenGrep",
		CICD_SecretsScan:  "Gitleaks",
		CICD_Signing:      "Cosign",
		DependencyMonitor: "Renovate",
		SCM:               "GitHub",
		DefectTracking:    "GitHub Issues",
		ResourceLimits:    "CPU: 200m, Memory: 256Mi",
	},
}

func TestEvaluate_NotApplicable(t *testing.T) {
	tests := []struct {
		name         string
		ruleVersion  string
		ruleTitle    string
		checkContent string
		discussion   string
	}{
		{
			name:         "SOAP not used",
			ruleVersion:  "APSC-DV-999001",
			ruleTitle:    "The application must use SOAP messaging securely.",
			checkContent: "Verify SOAP configuration.",
			discussion:   "SOAP security.",
		},
		{
			name:         "SAML assertion not used",
			ruleVersion:  "APSC-DV-999002",
			ruleTitle:    "The application must validate SAML assertion timestamps.",
			checkContent: "Verify SAML assertions.",
			discussion:   "SAML validation.",
		},
		{
			name:         "classified data marking",
			ruleVersion:  "APSC-DV-000110",
			ruleTitle:    "The application must associate security attributes.",
			checkContent: "Verify data marking.",
			discussion:   "Security attributes.",
		},
		{
			name:         "password rules",
			ruleVersion:  "APSC-DV-001680",
			ruleTitle:    "The application must enforce password length.",
			checkContent: "Verify password policy.",
			discussion:   "Password requirements.",
		},
		{
			name:         "PKI rules",
			ruleVersion:  "APSC-DV-001550",
			ruleTitle:    "The application must validate PKI certificates.",
			checkContent: "Verify PKI config.",
			discussion:   "PKI authentication.",
		},
		{
			name:         "shared/group accounts",
			ruleVersion:  "APSC-DV-999003",
			ruleTitle:    "The application must not use shared or group account credentials.",
			checkContent: "Verify shared accounts.",
			discussion:   "Account management.",
		},
		{
			name:         "temporary accounts",
			ruleVersion:  "APSC-DV-999004",
			ruleTitle:    "The application must manage temporary account access.",
			checkContent: "Verify temporary account handling.",
			discussion:   "Account lifecycle.",
		},
		{
			name:         "emergency accounts",
			ruleVersion:  "APSC-DV-999005",
			ruleTitle:    "The application must track emergency account usage.",
			checkContent: "Verify emergency account tracking.",
			discussion:   "Emergency access.",
		},
		{
			name:         "data mining",
			ruleVersion:  "APSC-DV-999006",
			ruleTitle:    "The application must protect against data mining.",
			checkContent: "Verify data mining protection.",
			discussion:   "Data mining risk.",
		},
		{
			name:         "non-local maintenance",
			ruleVersion:  "APSC-DV-999007",
			ruleTitle:    "The application must protect non-local maintenance sessions.",
			checkContent: "Verify non-local maintenance.",
			discussion:   "Remote access.",
		},
		{
			name:         "XML DoS",
			ruleVersion:  "APSC-DV-999008",
			ruleTitle:    "The application must protect XML parser from DoS attack.",
			checkContent: "Verify XML processing.",
			discussion:   "XML security.",
		},
		{
			name:         "security function testing",
			ruleVersion:  "APSC-DV-002760",
			ruleTitle:    "Security function verification.",
			checkContent: "Verify testing.",
			discussion:   "Security testing.",
		},
		{
			name:         "transaction recovery",
			ruleVersion:  "APSC-DV-999009",
			ruleTitle:    "The application must support transaction recovery.",
			checkContent: "Verify transaction recovery.",
			discussion:   "Transaction management.",
		},
		{
			name:         "key exchange",
			ruleVersion:  "APSC-DV-999010",
			ruleTitle:    "The application must use approved key exchange methods.",
			checkContent: "Verify key exchange.",
			discussion:   "Cryptographic key exchange.",
		},
		{
			name:         "device reauthentication",
			ruleVersion:  "APSC-DV-001530",
			ruleTitle:    "The application must reauthenticate devices.",
			checkContent: "Verify device auth.",
			discussion:   "Device authentication.",
		},
		{
			name:         "last logon display",
			ruleVersion:  "APSC-DV-000580",
			ruleTitle:    "Display last logon information.",
			checkContent: "Check last logon.",
			discussion:   "Session info.",
		},
		{
			name:         "CM repos",
			ruleVersion:  "APSC-DV-002995",
			ruleTitle:    "Source code management.",
			checkContent: "Verify SCM.",
			discussion:   "Configuration management.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, details, _ := Evaluate(evalProfile, "V-999999", tt.ruleVersion, tt.ruleTitle, tt.checkContent, tt.discussion)
			require.Equal(t, "not_applicable", status, "expected not_applicable for %s, got %s: %s", tt.name, status, details)
			require.NotEmpty(t, details)
		})
	}
}

func TestEvaluate_NotAFinding(t *testing.T) {
	tests := []struct {
		name         string
		ruleVersion  string
		ruleTitle    string
		checkContent string
		discussion   string
	}{
		{
			name:         "TLS/encryption",
			ruleVersion:  "APSC-DV-000160",
			ruleTitle:    "Implement DoD-approved encryption.",
			checkContent: "Verify TLS.",
			discussion:   "Encryption.",
		},
		{
			name:         "access control",
			ruleVersion:  "APSC-DV-000460",
			ruleTitle:    "Enforce approved authorizations.",
			checkContent: "Verify access control.",
			discussion:   "Authorization.",
		},
		{
			name:         "non-privileged users",
			ruleVersion:  "APSC-DV-000500",
			ruleTitle:    "Prevent non-privileged users from executing privileged functions.",
			checkContent: "Verify privilege separation.",
			discussion:   "Privileges.",
		},
		{
			name:         "execute without excessive permissions",
			ruleVersion:  "APSC-DV-000510",
			ruleTitle:    "Execute without excessive privileges.",
			checkContent: "Verify permissions.",
			discussion:   "Execution privileges.",
		},
		{
			name:         "account lockout",
			ruleVersion:  "APSC-DV-000530",
			ruleTitle:    "Enforce account lockout.",
			checkContent: "Verify lockout.",
			discussion:   "Lockout policy.",
		},
		{
			name:         "session limiting",
			ruleVersion:  "APSC-DV-000010",
			ruleTitle:    "Limit logon sessions per user.",
			checkContent: "Verify session limits.",
			discussion:   "Session management.",
		},
		{
			name:         "session cookie HTTPOnly",
			ruleVersion:  "APSC-DV-002210",
			ruleTitle:    "Session cookies HTTPOnly.",
			checkContent: "Verify cookie flags.",
			discussion:   "Cookie security.",
		},
		{
			name:         "XSS protection",
			ruleVersion:  "APSC-DV-002490",
			ruleTitle:    "Protect against XSS.",
			checkContent: "Verify XSS.",
			discussion:   "XSS.",
		},
		{
			name:         "buffer overflow (memory-safe language)",
			ruleVersion:  "APSC-DV-002590",
			ruleTitle:    "Protect against overflow.",
			checkContent: "Verify overflow protection.",
			discussion:   "Memory safety.",
		},
		{
			name:         "error messages",
			ruleVersion:  "APSC-DV-002570",
			ruleTitle:    "Error handling.",
			checkContent: "Verify error messages.",
			discussion:   "Error disclosure.",
		},
		{
			name:         "fail secure",
			ruleVersion:  "APSC-DV-002310",
			ruleTitle:    "Fail to a known safe state.",
			checkContent: "Verify fail-safe.",
			discussion:   "Failure handling.",
		},
		{
			name:         "process isolation",
			ruleVersion:  "APSC-DV-002370",
			ruleTitle:    "Isolate processes.",
			checkContent: "Verify isolation.",
			discussion:   "Process isolation.",
		},
		{
			name:         "DoD banner",
			ruleVersion:  "APSC-DV-000550",
			ruleTitle:    "Display DoD notice.",
			checkContent: "Verify banner.",
			discussion:   "Notice and consent.",
		},
		{
			name:         "embedded credentials",
			ruleVersion:  "APSC-DV-003110",
			ruleTitle:    "No embedded auth data.",
			checkContent: "Verify no hardcoded creds.",
			discussion:   "Credential storage.",
		},
		{
			name:         "crypto hashing of files",
			ruleVersion:  "APSC-DV-003140",
			ruleTitle:    "Crypto hash files.",
			checkContent: "Verify hashing.",
			discussion:   "File integrity.",
		},
		{
			name:         "STIG compliance",
			ruleVersion:  "APSC-DV-002970",
			ruleTitle:    "Apply STIG.",
			checkContent: "Verify STIG.",
			discussion:   "Compliance.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, details, _ := Evaluate(evalProfile, "V-999999", tt.ruleVersion, tt.ruleTitle, tt.checkContent, tt.discussion)
			require.Equal(t, "not_a_finding", status, "expected not_a_finding for %s, got %s: %s", tt.name, status, details)
			require.NotEmpty(t, details)
		})
	}
}

func TestEvaluate_NotReviewed(t *testing.T) {
	tests := []struct {
		name        string
		ruleVersion string
		ruleTitle   string
	}{
		{
			name:        "audit trail retention",
			ruleVersion: "APSC-DV-002900",
			ruleTitle:   "Retain audit records.",
		},
		{
			name:        "threat model",
			ruleVersion: "APSC-DV-003230",
			ruleTitle:   "Maintain threat model.",
		},
		{
			name:        "incident response plan",
			ruleVersion: "APSC-DV-003236",
			ruleTitle:   "Incident response plan.",
		},
		{
			name:        "unknown rule falls through",
			ruleVersion: "APSC-DV-999999",
			ruleTitle:   "Some unknown requirement with no keywords.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, details, _ := Evaluate(evalProfile, "V-999999", tt.ruleVersion, tt.ruleTitle, "Check it.", "Discussion.")
			require.Equal(t, "not_reviewed", status, "expected not_reviewed for %s, got %s: %s", tt.name, status, details)
			require.NotEmpty(t, details)
		})
	}
}

func TestEvaluate_FindingDetailsContainAppName(t *testing.T) {
	status, details, _ := Evaluate(evalProfile, "V-100001", "APSC-DV-000160", "Encryption", "Check TLS.", "TLS discussion.")
	require.Equal(t, "not_a_finding", status)
	require.Contains(t, details, "eval-app")
}

func TestEvaluate_ProfileCharacteristicsAffectResult(t *testing.T) {
	// With SOAP enabled, SOAP rules should NOT be not_applicable
	soapProfile := &Profile{
		AppName: "soap-app",
		Chars: Characteristics{
			UsesSOAP: true,
			Language: "java",
		},
		Platform: PlatformConfig{
			AuthProvider: "Keycloak",
			ServiceMesh:  "Istio",
		},
	}

	status, _, _ := Evaluate(soapProfile, "V-999999", "APSC-DV-999001",
		"The application must use SOAP messaging securely.", "Check SOAP.", "SOAP security.")
	// Should NOT be not_applicable since SOAP is used
	require.NotEqual(t, "not_applicable", status)
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substrs  []string
		expected bool
	}{
		{"match first", "hello world", []string{"hello", "foo"}, true},
		{"match second", "hello world", []string{"foo", "world"}, true},
		{"no match", "hello world", []string{"foo", "bar"}, false},
		{"case insensitive", "Hello World", []string{"hello"}, true},
		{"empty string", "", []string{"foo"}, false},
		{"empty substrs", "hello", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsAny(tt.s, tt.substrs...)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestInSet(t *testing.T) {
	tests := []struct {
		name     string
		val      string
		set      []string
		expected bool
	}{
		{"found", "a", []string{"a", "b", "c"}, true},
		{"not found", "d", []string{"a", "b", "c"}, false},
		{"empty set", "a", []string{}, false},
		{"exact match required", "ab", []string{"a", "b"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inSet(tt.val, tt.set...)
			require.Equal(t, tt.expected, result)
		})
	}
}
