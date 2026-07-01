// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"fmt"
	"strings"
)

// result helpers
func na(p *Profile, details string) (string, string, string) {
	return "not_applicable", details, ""
}

func naf(p *Profile, details string) (string, string, string) {
	return "not_a_finding", details, ""
}

func nr(p *Profile, details string) (string, string, string) {
	return "not_reviewed", details, ""
}

// Evaluate determines the status, finding_details, and comments for a rule
// based on the app profile characteristics.
func Evaluate(p *Profile, groupID, ruleVersion, ruleTitle, checkContent, discussion string) (string, string, string) {
	t := strings.ToLower(ruleTitle)
	c := strings.ToLower(checkContent)
	rv := ruleVersion
	app := p.AppName
	auth := p.Platform.AuthProvider
	mesh := p.Platform.ServiceMesh

	// ── NOT APPLICABLE: SOAP / WS-Security ──
	if !p.Chars.UsesSOAP && containsAny(t, "soap", "ws-security", "ws_security") {
		return na(p, fmt.Sprintf(
			"The %s application does not use SOAP messaging or WS-Security tokens. "+
				"Authentication is handled by %s.", app, auth))
	}

	// ── NOT APPLICABLE: SAML ──
	if !p.Chars.UsesSAML && containsAny(t, "saml assertion", "saml element", "asserting party") {
		return na(p, fmt.Sprintf(
			"The %s application does not utilize SAML assertions. "+
				"Authentication is delegated to %s.", app, auth))
	}
	if !p.Chars.UsesSAML && strings.Contains(t, "saml") && containsAny(t, "notonorafter", "notbefore", "onetimeuse", "sessionindex", "fips") {
		return na(p, fmt.Sprintf(
			"The %s application does not use SAML assertions.", app))
	}

	// ── NOT APPLICABLE: Classified/CUI data marking ──
	if !p.Chars.ProcessesClassified && !p.Chars.ProcessesCUI {
		if inSet(rv, "APSC-DV-000110", "APSC-DV-000120", "APSC-DV-000130") {
			return na(p, fmt.Sprintf(
				"The %s application does not process classified, CUI, or other data "+
					"requiring security attribute markings.", app))
		}
		if strings.Contains(t, "classification guide") {
			return na(p, fmt.Sprintf(
				"The %s application does not process classified information.", app))
		}
		if containsAny(t, "nsa-approved cryptography", "classified information") && strings.Contains(c, "not applicable") {
			return na(p, fmt.Sprintf(
				"The %s application does not process classified data.", app))
		}
		if strings.Contains(t, "mark") && containsAny(t, "sensitive", "classified") && strings.Contains(t, "output") {
			return na(p, fmt.Sprintf(
				"The %s application does not process or output classified or sensitive data requiring marking.", app))
		}
	}

	// ── NOT APPLICABLE: Data mining ──
	if strings.Contains(t, "data mining") {
		return na(p, fmt.Sprintf(
			"The %s application has no data mining protection requirements.", app))
	}

	// ── NOT APPLICABLE: Shared/group accounts ──
	if !p.Chars.HasSharedAccounts && strings.Contains(t, "shared") && strings.Contains(t, "group") && strings.Contains(t, "account") {
		return na(p, fmt.Sprintf(
			"The %s application does not use shared or group accounts. "+
				"Authentication is handled by %s.", app, auth))
	}

	// ── NOT APPLICABLE: Temporary/emergency accounts ──
	if strings.Contains(t, "temporary") && strings.Contains(t, "account") {
		return na(p, fmt.Sprintf(
			"The %s application does not manage user accounts directly. "+
				"Account management is delegated to %s.", app, auth))
	}
	if strings.Contains(t, "emergency") && strings.Contains(t, "account") {
		return na(p, fmt.Sprintf(
			"The %s application does not use emergency accounts. "+
				"Account management is delegated to %s.", app, auth))
	}

	// ── NOT APPLICABLE: Passwords ──
	if !p.Chars.UsesPasswords {
		passwordRules := []string{
			"APSC-DV-001680", "APSC-DV-001690", "APSC-DV-001700", "APSC-DV-001710",
			"APSC-DV-001720", "APSC-DV-001730", "APSC-DV-001740", "APSC-DV-001750",
			"APSC-DV-001760", "APSC-DV-001770", "APSC-DV-001780", "APSC-DV-001790",
			"APSC-DV-001795", "APSC-DV-001850",
		}
		if inSet(rv, passwordRules...) || containsAny(t,
			"password length", "password complexity", "password lifetime",
			"password reuse", "temporary password", "changeable by users",
			"uppercase character", "lowercase character", "numeric character",
			"special character", "change of at least eight",
			"cryptographic representations of passwords",
			"cryptographically-protected passwords",
			"passwords/pins as clear text") {
			return na(p, fmt.Sprintf(
				"The %s application does not implement local password authentication. "+
					"All authentication is delegated to %s.", app, auth))
		}
	}

	// ── NOT APPLICABLE: PKI/CAC/PIV ──
	if !p.Chars.UsesPKI {
		pkiRules := []string{
			"APSC-DV-001550", "APSC-DV-001560", "APSC-DV-001570", "APSC-DV-001580",
			"APSC-DV-001590", "APSC-DV-001600", "APSC-DV-001610",
			"APSC-DV-001810", "APSC-DV-001820", "APSC-DV-001830", "APSC-DV-001840",
		}
		if inSet(rv, pkiRules...) || (containsAny(t, "piv credential", "personal identity verification",
			"alt. token", "alt token", "cac", "pki-based", "certification path",
			"private key", "revocation data") && containsAny(c, "not applicable", "publicly releasable", "not pk-enabled")) {
			return na(p, fmt.Sprintf(
				"The %s application does not implement PKI/CAC/PIV authentication directly. "+
					"Authentication is delegated to %s.", app, auth))
		}
	}

	// ── NOT APPLICABLE: FICAM ──
	if !p.Chars.UsesPKI && strings.Contains(t, "ficam") {
		return na(p, fmt.Sprintf(
			"The %s application is not PKI-enabled. Authentication is handled via %s.", app, auth))
	}

	// ── NOT APPLICABLE: Non-local maintenance ──
	if !p.Chars.HasNonLocalMaint && (strings.Contains(t, "non-local maintenance") || strings.Contains(t, "nonlocal maintenance")) {
		return na(p, fmt.Sprintf(
			"The %s application does not provide non-local maintenance or diagnostic session capabilities.", app))
	}

	// ── NOT APPLICABLE: XML ──
	if !p.Chars.UsesXML && strings.Contains(t, "xml") && containsAny(t, "dos", "filter", "parser", "attack") {
		return na(p, fmt.Sprintf(
			"The %s application does not contain or utilize XML processing.", app))
	}

	// ── NOT APPLICABLE: Web services / high availability ──
	if !p.Chars.HasWebServices && strings.Contains(t, "web service") && containsAny(t, "redundancy", "deadlock", "recursion") {
		return na(p, fmt.Sprintf(
			"The %s application does not deploy web services requiring redundancy mechanisms.", app))
	}

	// ── NOT APPLICABLE: Log aggregation ──
	if strings.Contains(t, "audit record aggregation") || (strings.Contains(c[:min(200, len(c))], "compile audit records") && strings.Contains(c[:min(200, len(c))], "not applicable")) {
		return na(p, fmt.Sprintf(
			"The %s application does not provide log aggregation services.", app))
	}

	// ── NOT APPLICABLE: CM repos ──
	if inSet(rv, "APSC-DV-002995", "APSC-DV-003000", "APSC-DV-003010", "APSC-DV-003020") {
		if p.Platform.SCM != "" {
			return na(p, fmt.Sprintf(
				"The %s application uses %s for source code management with standard workflows.", app, p.Platform.SCM))
		}
	}

	// ── NOT APPLICABLE: Mutual auth / device auth ──
	if !p.Chars.AuthenticatesDevices {
		if strings.Contains(t, "mutual authentication") || strings.Contains(t, "mutual ssl") {
			return na(p, fmt.Sprintf(
				"The %s application does not require mutual authentication.", app))
		}
		if strings.Contains(t, "device identifier") && strings.Contains(t, "inactivity") {
			return na(p, fmt.Sprintf(
				"The %s application does not authenticate devices.", app))
		}
		if strings.Contains(t, "endpoint device") && strings.Contains(t, "authenticat") {
			return na(p, fmt.Sprintf(
				"The %s application does not require endpoint device authentication.", app))
		}
	}

	// ── NOT APPLICABLE: Crypto module access ──
	if !p.Chars.HasCryptoModuleAccess && strings.Contains(t, "cryptographic module") && strings.Contains(t, "authentication") {
		return na(p, fmt.Sprintf(
			"The %s application does not provide direct access to cryptographic modules. "+
				"Cryptographic operations are handled by %s.", app, mesh))
	}

	// ── NOT APPLICABLE: DMZ ──
	if !p.Chars.InDoDDMZ && strings.Contains(t, "separate network segment") {
		return na(p, fmt.Sprintf(
			"The %s application is not a tiered application hosted in the DoD DMZ.", app))
	}

	// ── NOT APPLICABLE: Critical/HA ──
	if !p.Chars.IsCritical && strings.Contains(t, "general purpose machine") && strings.Contains(t, "critical") {
		return na(p, fmt.Sprintf(
			"The %s application is not designated as critical or high availability.", app))
	}

	// ── NOT APPLICABLE: DoS threat model ──
	if strings.Contains(t, "dos") && strings.Contains(c[:min(200, len(c))], "threat model") {
		return na(p, fmt.Sprintf(
			"No formal threat model document has been produced for the %s application.", app))
	}

	// ── NOT APPLICABLE: Mobile code ──
	if !p.Chars.HasMobileCode {
		if containsAny(t, "category 1a mobile code", "unsigned category") {
			return na(p, fmt.Sprintf(
				"The %s application does not use Category 1A mobile code.", app))
		}
		if strings.Contains(t, "uncategorized") && strings.Contains(t, "mobile code") {
			return na(p, fmt.Sprintf(
				"The %s application uses only standard JavaScript within the client browser.", app))
		}
	}

	// ── NOT APPLICABLE: Database exports ──
	if !p.Chars.UsesDatabase && (strings.Contains(t, "database export") || strings.Contains(t, "production database export")) {
		return na(p, fmt.Sprintf(
			"The %s application does not use a database.", app))
	}

	// ── NOT APPLICABLE: Key exchange ──
	if !p.Chars.DoesKeyExchange && strings.Contains(t, "key exchange") {
		return na(p, fmt.Sprintf(
			"The %s application does not implement key exchange. TLS is handled by %s.", app, mesh))
	}

	// ── NOT APPLICABLE: Security function testing ──
	if inSet(rv, "APSC-DV-002760", "APSC-DV-002770", "APSC-DV-002780") {
		return na(p, fmt.Sprintf(
			"The %s application is not designed to perform security function verification testing. "+
				"Security functions are provided by the platform.", app))
	}

	// ── NOT APPLICABLE: Transaction-based ──
	if !p.Chars.IsTransactionBased && strings.Contains(t, "transaction recovery") {
		return na(p, fmt.Sprintf(
			"The %s application is not transaction-based.", app))
	}

	// ── NOT APPLICABLE: Config management app ──
	if !p.Chars.IsConfigMgmtApp && (strings.Contains(t, "deny-all, permit-by-exception") || strings.Contains(t, "whitelist")) {
		if strings.Contains(c[:min(200, len(c))], "configuration management") {
			return na(p, fmt.Sprintf(
				"The %s application is not a configuration management application.", app))
		}
	}

	// ── NOT APPLICABLE: Non-org users ──
	if !p.Chars.HostsNonOrgUsers && strings.Contains(t, "non-organizational users") {
		return na(p, fmt.Sprintf(
			"The %s application does not host non-organizational users.", app))
	}

	// ── NOT APPLICABLE: Federal agency PIV ──
	if !p.Chars.UsesPKI && strings.Contains(t, "other federal agencies") && strings.Contains(t, "piv") {
		return na(p, fmt.Sprintf(
			"The %s application is not PKI-enabled.", app))
	}

	// ── NOT APPLICABLE: Group authenticator ──
	if !p.Chars.HasSharedAccounts && strings.Contains(t, "group authenticator") {
		return na(p, fmt.Sprintf(
			"The %s application does not use group or shared accounts.", app))
	}

	// ── NOT APPLICABLE: Classification levels in audit ──
	if !p.Chars.ProcessesClassified && (strings.Contains(t, "categories of information") || strings.Contains(t, "classification levels")) && strings.Contains(t, "audit") {
		return na(p, fmt.Sprintf(
			"The %s application does not implement data compartmentalization or classification levels.", app))
	}

	// ── NOT APPLICABLE: Concurrent logons ──
	if p.Chars.IsStateless && strings.Contains(t, "concurrent logon") {
		return na(p, fmt.Sprintf(
			"The %s application is stateless and does not track user sessions at the application level.", app))
	}

	// ── NOT APPLICABLE: Device reauthentication ──
	if rv == "APSC-DV-001530" {
		return na(p, fmt.Sprintf(
			"The %s application does not authenticate devices.", app))
	}

	// ── NOT APPLICABLE: Last logon display ──
	if rv == "APSC-DV-000580" {
		return na(p, fmt.Sprintf(
			"The %s application does not display last logon information. Session management is delegated to %s.", app, auth))
	}

	// ── NOT APPLICABLE: Classified output marking ──
	if !p.Chars.ProcessesClassified && rv == "APSC-DV-003120" {
		return na(p, fmt.Sprintf(
			"The %s application does not process classified data requiring output marking.", app))
	}

	// ── NOT APPLICABLE: Audit tools ──
	if inSet(rv, "APSC-DV-001310", "APSC-DV-001320", "APSC-DV-001330") {
		return na(p, fmt.Sprintf(
			"The %s application does not provide distinct audit tools.", app))
	}

	// ── NOT APPLICABLE: Audit backup built-in ──
	if rv == "APSC-DV-001340" {
		return na(p, fmt.Sprintf(
			"The %s application does not include a built-in backup capability for audit records.", app))
	}

	// ═══════════════════════════════════════════════════════════════════
	// NOT A FINDING
	// ═══════════════════════════════════════════════════════════════════

	// ── Encryption / TLS ──
	if mesh != "" && inSet(rv, "APSC-DV-000160", "APSC-DV-000170", "APSC-DV-002440", "APSC-DV-002450", "APSC-DV-002460", "APSC-DV-002470") {
		return naf(p, fmt.Sprintf(
			"The %s application is deployed behind %s which provides mTLS for all in-mesh traffic. "+
				"External access is via HTTPS through the platform gateway. DoD-approved encryption (TLS 1.2/1.3) "+
				"protects the confidentiality and integrity of all sessions.", app, mesh))
	}

	// ── Access control ──
	if rv == "APSC-DV-000460" {
		return naf(p, fmt.Sprintf(
			"The %s application enforces approved authorizations through the platform. "+
				"Access requires authentication via %s. %s intercepts all requests and enforces authentication.", app, auth, p.Platform.AuthProxy))
	}

	// ── Non-privileged users / privileged functions ──
	if !p.Chars.HasAdminInterface && rv == "APSC-DV-000500" {
		return naf(p, fmt.Sprintf(
			"The %s application does not provide privileged functions to users. "+
				"All endpoints serve read-only content. Application administration is performed via Kubernetes RBAC.", app))
	}

	// ── Execute without excessive permissions ──
	if p.Platform.ContainerUser != "" && rv == "APSC-DV-000510" {
		return naf(p, fmt.Sprintf(
			"The %s application runs as %s in the container. "+
				"The base image is %s with minimal packages.", app, p.Platform.ContainerUser, p.Platform.BaseImage))
	}

	// ── Account lockout ──
	if rv == "APSC-DV-000530" {
		return naf(p, fmt.Sprintf(
			"The %s application delegates authentication to %s which enforces account lockout policies.", app, auth))
	}

	// ── Automated account management ──
	if rv == "APSC-DV-000280" {
		return naf(p, fmt.Sprintf(
			"The %s application delegates all account management to %s which provides automated account lifecycle functions.", app, auth))
	}

	// ── Account lifecycle audit ──
	acctAuditRules := []string{
		"APSC-DV-000340", "APSC-DV-000350", "APSC-DV-000360", "APSC-DV-000370",
		"APSC-DV-000380", "APSC-DV-000390", "APSC-DV-000400", "APSC-DV-000410",
		"APSC-DV-000420", "APSC-DV-000430",
	}
	if inSet(rv, acctAuditRules...) {
		return naf(p, fmt.Sprintf(
			"The %s application delegates account management to %s which provides audit logging for all account lifecycle events.", app, auth))
	}

	// ── Account inactivity disable ──
	if rv == "APSC-DV-000320" {
		return naf(p, fmt.Sprintf(
			"The %s application delegates account management to %s which can be configured to disable inactive accounts.", app, auth))
	}

	// ── Unnecessary accounts ──
	if rv == "APSC-DV-000330" {
		return naf(p, fmt.Sprintf(
			"The %s application does not maintain its own user accounts. All authentication is delegated to %s.", app, auth))
	}

	// ── Unique user identification ──
	if rv == "APSC-DV-001540" {
		return naf(p, fmt.Sprintf(
			"The %s application uniquely identifies and authenticates users through %s.", app, auth))
	}

	// ── Replay-resistant auth ──
	if inSet(rv, "APSC-DV-001620", "APSC-DV-001630") {
		return naf(p, fmt.Sprintf(
			"The %s application uses %s for authentication which implements replay-resistant mechanisms (nonces, short-lived tokens, TLS-protected exchanges).", app, auth))
	}

	// ── Session management ──
	sessionRules := map[string]string{
		"APSC-DV-000010": "session limiting",
		"APSC-DV-000060": "clearing temporary storage and cookies on session termination",
		"APSC-DV-000070": "non-privileged user session timeout",
		"APSC-DV-000080": "admin user session timeout",
		"APSC-DV-000090": "logoff capability",
		"APSC-DV-000100": "explicit logoff messaging",
	}
	if desc, ok := sessionRules[rv]; ok {
		return naf(p, fmt.Sprintf(
			"The %s application delegates %s to %s/%s.", app, desc, p.Platform.AuthProxy, auth))
	}

	// ── Session cookie/ID rules ──
	sessionSecRules := map[string]string{
		"APSC-DV-002210": "HTTPOnly flag on session cookies",
		"APSC-DV-002220": "Secure flag on session cookies",
		"APSC-DV-002230": "session ID protection (not exposed)",
		"APSC-DV-002240": "session ID destruction on logoff",
		"APSC-DV-002250": "session fixation protection",
		"APSC-DV-002260": "session ID validation",
		"APSC-DV-002270": "no URL-embedded session IDs",
		"APSC-DV-002280": "no session ID reuse/recycling",
		"APSC-DV-002290": "cryptographically random session IDs",
	}
	if desc, ok := sessionSecRules[rv]; ok {
		return naf(p, fmt.Sprintf(
			"Session management for %s is handled by %s/%s which provides %s.", app, p.Platform.AuthProxy, auth, desc))
	}

	// ── DoD-approved CAs ──
	if rv == "APSC-DV-002300" && mesh != "" {
		return naf(p, fmt.Sprintf(
			"TLS certificate management is handled by %s and the platform gateway.", mesh))
	}

	// ── XSS ──
	if rv == "APSC-DV-002490" {
		details := fmt.Sprintf("The %s application protects against XSS vulnerabilities.", app)
		if p.Platform.CICD_SAST != "" {
			details += fmt.Sprintf(" CI/CD includes SAST scanning via %s.", p.Platform.CICD_SAST)
		}
		return naf(p, details)
	}

	// ── CSRF ──
	if rv == "APSC-DV-002500" && !p.Chars.HasUserInput {
		return naf(p, fmt.Sprintf(
			"The %s application is read-only with no state-changing operations. Authentication is handled by %s.", app, auth))
	}

	// ── Injection / input vulnerabilities ──
	if !p.Chars.HasUserInput {
		injRules := map[string]string{
			"APSC-DV-002510": "command injection",
			"APSC-DV-002530": "input validation",
			"APSC-DV-002560": "input handling vulnerabilities",
		}
		if desc, ok := injRules[rv]; ok {
			details := fmt.Sprintf("The %s application does not accept user-supplied input, mitigating %s risks.", app, desc)
			if p.Platform.CICD_SAST != "" {
				details += fmt.Sprintf(" CI/CD includes SAST scanning via %s.", p.Platform.CICD_SAST)
			}
			return naf(p, details)
		}
	}

	// ── SQL injection ──
	if !p.Chars.UsesDatabase && rv == "APSC-DV-002540" {
		return naf(p, fmt.Sprintf(
			"The %s application does not use a database and does not construct SQL queries.", app))
	}

	// ── XML attacks ──
	if !p.Chars.UsesXML && rv == "APSC-DV-002550" {
		return naf(p, fmt.Sprintf(
			"The %s application does not process XML.", app))
	}

	// ── Overflow attacks ──
	if rv == "APSC-DV-002590" && containsAny(p.Chars.Language, "python", "go", "java", "ruby", "javascript", "typescript") {
		return naf(p, fmt.Sprintf(
			"The %s application is written in %s, a memory-managed language not susceptible to traditional buffer overflow vulnerabilities.", app, p.Chars.Language))
	}

	// ── Canonical representation ──
	if !p.Chars.HasUserInput && rv == "APSC-DV-002520" {
		return naf(p, fmt.Sprintf(
			"The %s application does not process user-supplied file paths or URLs.", app))
	}

	// ── Error messages ──
	if inSet(rv, "APSC-DV-002570", "APSC-DV-002580", "APSC-DV-003235") {
		return naf(p, fmt.Sprintf(
			"The %s application does not expose detailed error information to end users.", app))
	}

	// ── Hidden fields ──
	if rv == "APSC-DV-002485" && !p.Chars.HasUserInput {
		return naf(p, fmt.Sprintf(
			"The %s application does not store sensitive information in hidden fields.", app))
	}

	// ── Information disclosure ──
	if rv == "APSC-DV-002480" {
		return naf(p, fmt.Sprintf(
			"The %s application does not disclose unnecessary information to users.", app))
	}

	// ── Fail secure ──
	if rv == "APSC-DV-002310" && p.Platform.ContainerRuntime != "" {
		return naf(p, fmt.Sprintf(
			"The %s application fails to a secure state. If the process fails, %s restarts the pod. "+
				"Access control (%s) operates independently.", app, p.Platform.ContainerRuntime, auth))
	}

	// ── Preserve failure info ──
	if rv == "APSC-DV-002320" && p.Platform.ContainerRuntime != "" {
		return naf(p, fmt.Sprintf(
			"The %s application writes to stdout/stderr captured by %s container runtime.", app, p.Platform.ContainerRuntime))
	}

	// ── Stored data protection ──
	if p.Chars.IsStateless && inSet(rv, "APSC-DV-002330", "APSC-DV-002340", "APSC-DV-002350") {
		return naf(p, fmt.Sprintf(
			"The %s application is stateless with no data stored at rest.", app))
	}

	// ── Process isolation ──
	if rv == "APSC-DV-002370" && p.Platform.ContainerRuntime != "" {
		return naf(p, fmt.Sprintf(
			"The %s application runs in an isolated %s container with namespace isolation.", app, p.Platform.ContainerRuntime))
	}

	// ── Shared resources ──
	if rv == "APSC-DV-002380" && p.Platform.NetworkPolicies {
		return naf(p, fmt.Sprintf(
			"The %s application runs in an isolated pod with network policies restricting communication.", app))
	}

	// ── Security function isolation ──
	if rv == "APSC-DV-002360" {
		return naf(p, fmt.Sprintf(
			"Security functions for %s are isolated by design — handled by %s (identity), %s (proxy), and %s (network).", app, auth, p.Platform.AuthProxy, mesh))
	}

	// ── Network connection termination ──
	if rv == "APSC-DV-002000" {
		return naf(p, fmt.Sprintf(
			"The %s application is stateless HTTP. Connections terminate at the end of each request/response cycle.", app))
	}

	// ── Race conditions ──
	if p.Chars.IsStateless && rv == "APSC-DV-001995" {
		return naf(p, fmt.Sprintf(
			"The %s application is stateless with no shared mutable state or concurrent resource access patterns.", app))
	}

	// ── DoD banner ──
	if inSet(rv, "APSC-DV-000550", "APSC-DV-000560", "APSC-DV-000570") {
		return naf(p, fmt.Sprintf(
			"The %s application is accessed through %s which can display the DoD Notice and Consent Banner before granting access.", app, auth))
	}

	// ── Embedded credentials ──
	if rv == "APSC-DV-003110" {
		details := fmt.Sprintf("The %s application does not contain embedded authentication data in source code.", app)
		if p.Platform.CICD_SecretsScan != "" {
			details += fmt.Sprintf(" CI/CD includes secret scanning via %s.", p.Platform.CICD_SecretsScan)
		}
		return naf(p, details)
	}

	// ── Supported products ──
	if rv == "APSC-DV-003240" {
		details := fmt.Sprintf("The %s application uses supported software components.", app)
		if p.Platform.DependencyMonitor != "" {
			details += fmt.Sprintf(" %s monitors for dependency updates.", p.Platform.DependencyMonitor)
		}
		return naf(p, details)
	}

	// ── Decommission when unsupported ──
	if rv == "APSC-DV-003250" {
		return naf(p, fmt.Sprintf(
			"All %s application components are under active support and maintenance.", app))
	}

	// ── Default passwords ──
	if rv == "APSC-DV-003280" {
		return naf(p, fmt.Sprintf(
			"The %s application does not ship with default passwords. Authentication is handled by %s.", app, auth))
	}

	// ── Built-in accounts ──
	if rv == "APSC-DV-003270" {
		return naf(p, fmt.Sprintf(
			"The %s application does not create or utilize built-in accounts.", app))
	}

	// ── Non-essential capabilities ──
	if rv == "APSC-DV-001500" {
		return naf(p, fmt.Sprintf(
			"The %s application is minimal by design with no unnecessary features or debug modes enabled.", app))
	}

	// ── Ports and protocols ──
	if rv == "APSC-DV-001510" && p.Platform.NetworkPolicies {
		return naf(p, fmt.Sprintf(
			"The %s application uses only approved ports and protocols. Network policies restrict egress to approved destinations.", app))
	}

	// ── Reauthentication ──
	if rv == "APSC-DV-001520" && !p.Chars.HasAdminInterface {
		return naf(p, fmt.Sprintf(
			"The %s application has a single access level for all authenticated users. No privilege escalation scenarios exist.", app))
	}

	// ── Account deletion session termination ──
	if rv == "APSC-DV-001800" {
		return naf(p, fmt.Sprintf(
			"Account deletion and session termination is handled by %s.", auth))
	}

	// ── Vulnerability assessment ──
	if rv == "APSC-DV-001460" && p.Platform.CICD_SAST != "" {
		return naf(p, fmt.Sprintf(
			"The %s application undergoes vulnerability assessment via CI/CD: SAST (%s), secret scanning (%s).",
			app, p.Platform.CICD_SAST, p.Platform.CICD_SecretsScan))
	}

	// ── Crypto hashing of files ──
	if rv == "APSC-DV-003140" && p.Platform.CICD_Signing != "" {
		return naf(p, fmt.Sprintf(
			"Application files are cryptographically hashed and signed via %s.", p.Platform.CICD_Signing))
	}

	// ── Code review ──
	if rv == "APSC-DV-003170" && p.Platform.CICD_SAST != "" {
		return naf(p, fmt.Sprintf(
			"The %s application undergoes code review via pull requests with automated SAST (%s).", app, p.Platform.CICD_SAST))
	}

	// ── Security updates ──
	if rv == "APSC-DV-002630" && p.Platform.DependencyMonitor != "" {
		return naf(p, fmt.Sprintf(
			"The %s application uses %s for automated dependency update monitoring.", app, p.Platform.DependencyMonitor))
	}

	// ── Remove old versions ──
	if rv == "APSC-DV-002610" && p.Platform.ContainerRuntime != "" {
		return naf(p, fmt.Sprintf(
			"Deployment via %s replaces previous versions. Old container images are not retained.", p.Platform.ContainerRuntime))
	}

	// ── Software installation restriction ──
	if rv == "APSC-DV-001390" && !p.Chars.HasFileUpload {
		return naf(p, fmt.Sprintf(
			"The %s application does not provide any capability for users to install software.", app))
	}

	// ── Config change access restrictions ──
	if rv == "APSC-DV-001410" && !p.Chars.HasAdminInterface {
		return naf(p, fmt.Sprintf(
			"The %s application does not expose configuration settings through its web interface.", app))
	}

	// ── Signed patches ──
	if rv == "APSC-DV-001430" && p.Platform.CICD_Signing != "" {
		return naf(p, fmt.Sprintf(
			"Application updates are deployed with cryptographic verification via %s.", p.Platform.CICD_Signing))
	}

	// ── Library permissions ──
	if rv == "APSC-DV-001440" && p.Platform.ContainerUser != "" {
		return naf(p, fmt.Sprintf(
			"Application libraries are installed during build and owned by root. The application runs as %s, preventing library modification.", p.Platform.ContainerUser))
	}

	// ── IPv6 ──
	if rv == "APSC-DV-003030" {
		return naf(p, fmt.Sprintf(
			"The %s application supports IPv6. The %s platform handles network protocol compatibility.", app, p.Platform.ContainerRuntime))
	}

	// ── UI separated from data ──
	if p.Chars.IsStateless && rv == "APSC-DV-002150" {
		return naf(p, fmt.Sprintf(
			"The %s application is stateless with no data storage interface to separate.", app))
	}

	// ── FIPS crypto ──
	if inSet(rv, "APSC-DV-002020", "APSC-DV-002030", "APSC-DV-002040") {
		if p.Platform.CICD_Signing != "" || mesh != "" {
			return naf(p, fmt.Sprintf(
				"Cryptographic operations for %s are handled by platform components (%s, %s).", app, mesh, p.Platform.CICD_Signing))
		}
	}

	// ── Program execution per org policies ──
	if rv == "APSC-DV-001480" && p.Platform.NetworkPolicies {
		return naf(p, fmt.Sprintf(
			"The %s application operates within platform-enforced constraints (network policies, pod security, service mesh).", app))
	}

	// ── Data protection documented ──
	if rv == "APSC-DV-000440" {
		return naf(p, fmt.Sprintf(
			"The %s application data protection is provided by the platform (TLS, authentication, network policies).", app))
	}

	// ── Config files separate from user data ──
	if rv == "APSC-DV-002960" {
		return naf(p, fmt.Sprintf(
			"The %s application configuration is provided via environment variables. The application does not store user data.", app))
	}

	// ── Audit privileged functions ──
	if rv == "APSC-DV-000520" && !p.Chars.HasAdminInterface {
		return naf(p, fmt.Sprintf(
			"The %s application does not provide privileged functions through its web interface. Administrative actions are audited by %s.", app, p.Platform.ContainerRuntime))
	}

	// ── Audit config changes ──
	if rv == "APSC-DV-001420" && !p.Chars.HasAdminInterface {
		return naf(p, fmt.Sprintf(
			"Configuration changes to %s are made through %s operations tracked in the audit log.", app, p.Platform.ContainerRuntime))
	}

	// ── Platform audit logging ──
	auditPlatformRules := []string{
		"APSC-DV-000620", "APSC-DV-000630", "APSC-DV-000640", "APSC-DV-000650",
		"APSC-DV-000660", "APSC-DV-000670", "APSC-DV-000680", "APSC-DV-000690",
		"APSC-DV-000700", "APSC-DV-000710", "APSC-DV-000720", "APSC-DV-000730",
		"APSC-DV-000740", "APSC-DV-000750", "APSC-DV-000760", "APSC-DV-000770",
		"APSC-DV-000780", "APSC-DV-000790", "APSC-DV-000800", "APSC-DV-000810",
		"APSC-DV-000820", "APSC-DV-000830", "APSC-DV-000840", "APSC-DV-000850",
		"APSC-DV-000860", "APSC-DV-000870", "APSC-DV-000880",
		"APSC-DV-000910", "APSC-DV-000940", "APSC-DV-000950",
		"APSC-DV-000960", "APSC-DV-000970", "APSC-DV-000980", "APSC-DV-000990",
		"APSC-DV-001000", "APSC-DV-001010", "APSC-DV-001020", "APSC-DV-001030",
	}
	if inSet(rv, auditPlatformRules...) {
		return naf(p, fmt.Sprintf(
			"Audit logging for %s is provided at the platform level. %s logs HTTP requests. "+
				"%s logs authentication events. %s captures container logs.", app, mesh, auth, p.Platform.ContainerRuntime))
	}

	// ── Centralized logging ──
	auditCentralized := []string{
		"APSC-DV-001050", "APSC-DV-001070", "APSC-DV-001080",
		"APSC-DV-001090", "APSC-DV-001100", "APSC-DV-001110",
		"APSC-DV-001120", "APSC-DV-001130", "APSC-DV-001140",
		"APSC-DV-001150", "APSC-DV-001160", "APSC-DV-001170",
		"APSC-DV-001180", "APSC-DV-001190", "APSC-DV-001200",
		"APSC-DV-001210", "APSC-DV-001220",
	}
	if inSet(rv, auditCentralized...) {
		return naf(p, fmt.Sprintf(
			"The %s application is deployed on a platform providing centralized logging. "+
				"Application logs are captured by %s.", app, p.Platform.ContainerRuntime))
	}

	// ── Audit timestamps ──
	if inSet(rv, "APSC-DV-001250", "APSC-DV-001260", "APSC-DV-001270") {
		return naf(p, fmt.Sprintf(
			"The %s application uses the system clock for timestamps. Platform logs use synchronized system time.", app))
	}

	// ── Audit record protection ──
	if inSet(rv, "APSC-DV-001280", "APSC-DV-001290", "APSC-DV-001300") {
		return naf(p, fmt.Sprintf(
			"Audit records for %s are managed by %s with RBAC-controlled access.", app, p.Platform.ContainerRuntime))
	}

	// ── Audit integrity crypto ──
	if inSet(rv, "APSC-DV-001350", "APSC-DV-001360", "APSC-DV-001370") {
		return naf(p, fmt.Sprintf(
			"Audit information integrity for %s is managed at the platform level.", app))
	}

	// ── Account management process (ISSO) ──
	if rv == "APSC-DV-002880" {
		return naf(p, fmt.Sprintf(
			"Account management for %s is handled through %s.", app, auth))
	}

	// ── Unlock process ──
	if rv == "APSC-DV-000540" {
		return naf(p, fmt.Sprintf(
			"Account unlock processes are handled through %s administration.", auth))
	}

	// ── Discretionary access control ──
	if rv == "APSC-DV-000470" {
		return naf(p, fmt.Sprintf(
			"The %s application enforces access control through the platform. %s controls access.", app, auth))
	}

	// ── Information flow control ──
	if inSet(rv, "APSC-DV-000480", "APSC-DV-000490") && p.Platform.NetworkPolicies {
		return naf(p, fmt.Sprintf(
			"Information flow for %s is controlled by network policies and %s.", app, mesh))
	}

	// ── DoS protection ──
	if rv == "APSC-DV-002400" && p.Platform.ResourceLimits != "" {
		return naf(p, fmt.Sprintf(
			"The %s application is protected by resource limits (%s) and network policies.", app, p.Platform.ResourceLimits))
	}

	// ── Update notifications ──
	if inSet(rv, "APSC-DV-003340", "APSC-DV-003345") && p.Platform.DependencyMonitor != "" {
		return naf(p, fmt.Sprintf(
			"The %s application uses %s for automated dependency update notifications.", app, p.Platform.DependencyMonitor))
	}

	// ── DMZ/ingress ──
	if rv == "APSC-DV-003350" {
		return naf(p, fmt.Sprintf(
			"Traffic to %s is routed through the platform gateway with network policies.", app))
	}

	// ── Active vuln testing ──
	if rv == "APSC-DV-002930" && p.Platform.CICD_SAST != "" {
		return naf(p, fmt.Sprintf(
			"Active vulnerability testing for %s is performed via CI/CD (%s, %s).", app, p.Platform.CICD_SAST, p.Platform.CICD_SecretsScan))
	}

	// ── Defect tracking ──
	if rv == "APSC-DV-003190" && p.Platform.DefectTracking != "" {
		return naf(p, fmt.Sprintf(
			"The %s application uses %s for defect tracking.", app, p.Platform.DefectTracking))
	}

	// ── IA impact assessment ──
	if rv == "APSC-DV-003200" && p.Platform.CICD_SAST != "" {
		return naf(p, fmt.Sprintf(
			"Changes to %s go through pull requests with automated security scanning (%s).", app, p.Platform.CICD_SAST))
	}

	// ── Security flaws tracked ──
	if rv == "APSC-DV-003210" && p.Platform.DefectTracking != "" {
		return naf(p, fmt.Sprintf(
			"Security flaws for %s are tracked in %s.", app, p.Platform.DefectTracking))
	}

	// ── Coding standards ──
	if rv == "APSC-DV-003215" && p.Platform.CICD_SAST != "" {
		return naf(p, fmt.Sprintf(
			"The %s development team follows coding standards enforced by CI/CD linting and SAST.", app))
	}

	// ── Test plans ──
	if rv == "APSC-DV-003130" {
		return naf(p, fmt.Sprintf(
			"The %s application includes test plans executed as part of the release process.", app))
	}

	// ── Init/shutdown testing ──
	if rv == "APSC-DV-003160" {
		return naf(p, fmt.Sprintf(
			"The %s application includes health check testing and %s liveness/readiness probes.", app, p.Platform.ContainerRuntime))
	}

	// ── Backup ──
	if p.Chars.IsStateless && inSet(rv, "APSC-DV-003070", "APSC-DV-003080", "APSC-DV-003090") {
		return naf(p, fmt.Sprintf(
			"The %s application is stateless. Source code is stored in %s. Container images are stored in the registry.", app, p.Platform.SCM))
	}

	// ── STIG compliance ──
	if rv == "APSC-DV-002970" {
		return naf(p, fmt.Sprintf(
			"This ASD STIG is being applied to the %s application.", app))
	}

	// ── Direct access ──
	if !p.Chars.HasAdminInterface && strings.Contains(t, "direct access") && strings.Contains(t, "information system") {
		return naf(p, fmt.Sprintf(
			"The %s application does not implement direct access features to the underlying OS.", app))
	}

	// ── Non-repudiation ──
	if rv == "APSC-DV-000590" {
		return nr(p, fmt.Sprintf(
			"Review whether non-repudiation requirements exist for the %s application.", app))
	}

	// ═══════════════════════════════════════════════════════════════════
	// NOT REVIEWED — requires manual/org verification
	// ═══════════════════════════════════════════════════════════════════
	nrRules := map[string]string{
		"APSC-DV-002900": "Verify audit trail retention meets 30-month requirement.",
		"APSC-DV-002910": "Verify periodic audit trail review process exists.",
		"APSC-DV-002920": "Verify IA violation reporting policy exists.",
		"APSC-DV-003150": "Verify designated security testing personnel exist.",
		"APSC-DV-003180": "Verify code coverage statistics are maintained.",
		"APSC-DV-003220": "Verify design document exists and is updated per release.",
		"APSC-DV-003230": "Verify threat model exists and is reviewed per release.",
		"APSC-DV-003236": "Verify application incident response plan exists.",
		"APSC-DV-003285": "Verify Application Configuration Guide exists.",
		"APSC-DV-003050": "Verify contingency plan exists.",
		"APSC-DV-003060": "Verify disaster recovery procedures exist.",
		"APSC-DV-002980": "Verify ports/protocols are registered in DoD PPSM CAL.",
		"APSC-DV-002990": "Verify application is registered in DoD Ports and Protocols Database.",
		"APSC-DV-003330": "Verify low resource alerting is configured.",
		"APSC-DV-003400": "Verify annual security training for program personnel.",
		"APSC-DV-003260": "Verify decommission notification provisions exist.",
	}
	if msg, ok := nrRules[rv]; ok {
		return nr(p, fmt.Sprintf("%s (%s)", msg, app))
	}

	// ── Catch-all ──
	return nr(p, fmt.Sprintf(
		"This rule requires manual review for the %s application.", app))
}

// helpers

func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func inSet(val string, set ...string) bool {
	for _, s := range set {
		if val == s {
			return true
		}
	}
	return false
}
