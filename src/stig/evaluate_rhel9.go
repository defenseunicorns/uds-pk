// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"fmt"
	"strings"
)

// EvaluateRHEL9 provides broad posture-based auto-dispositions for host-focused
// RHEL 9 profiles. Rules not recognized here intentionally fall back to
// not_reviewed so they can be handled through profile overrides.
func EvaluateRHEL9(p *Profile, _ string, ruleVersion, ruleTitle, checkContent, _ string) (string, string, string) {
	t := strings.ToLower(ruleTitle)
	c := strings.ToLower(checkContent)
	host := p.AppName

	if ruleVersion == "" && ruleTitle == "" {
		return nr(p, "No RHEL 9 rule metadata available for evaluation.")
	}

	if !p.Chars.HasGUI && containsAny(t, "graphical", "gui", "gdm", "display manager") {
		return na(p, fmt.Sprintf("The %s host is configured as a non-GUI server platform.", host))
	}
	if p.Chars.BootsToMultiUser && containsAny(t, "multi-user.target", "graphical target", "default target") {
		return naf(p, fmt.Sprintf("The %s host boots to the multi-user target.", host))
	}
	if p.Chars.UsesFIPSMode && containsAny(t, "fips", "cryptographic module", "approved mode") {
		return naf(p, fmt.Sprintf("The %s host operates with FIPS mode enabled.", host))
	}
	if p.Chars.UsesSELinux && containsAny(t, "selinux", "mandatory access control") {
		return naf(p, fmt.Sprintf("SELinux is enabled for the %s host in %s mode.", host, coalesce(p.Platform.SELinuxMode, "enforcing")))
	}
	if p.Chars.UsesAuditd && containsAny(t, "audit", "auditd", "audit record") {
		return naf(p, fmt.Sprintf("The %s host uses %s for audit collection.", host, coalesce(p.Platform.AuditService, "auditd")))
	}
	if p.Chars.UsesJournald && containsAny(t, "journald", "systemd journal") {
		return naf(p, fmt.Sprintf("The %s host uses systemd-journald for local logging.", host))
	}
	if p.Chars.UsesFirewall && containsAny(t, "firewall", "firewalld", "packet filter") {
		return naf(p, fmt.Sprintf("The %s host uses %s to enforce host firewall policy.", host, coalesce(p.Platform.Firewall, "firewalld")))
	}
	if p.Chars.UsesSSH && containsAny(t, "ssh", "secure shell") {
		return naf(p, fmt.Sprintf("SSH access on the %s host is restricted to administrators.", host))
	}
	if p.Chars.UsesSudo && containsAny(t, "sudo", "privileged command", "elevated privilege") {
		return naf(p, fmt.Sprintf("The %s host uses sudo for privileged access.", host))
	}
	if p.Chars.UsesAIDE && containsAny(t, "aide", "file integrity") {
		return naf(p, fmt.Sprintf("The %s host uses %s for file integrity monitoring.", host, coalesce(p.Platform.FileIntegrity, "AIDE")))
	}
	if p.Chars.IsAirGapped && containsAny(t, "wireless", "internet", "external network", "public network") {
		return na(p, fmt.Sprintf("The %s host operates in a small air-gapped enclave with restricted external connectivity.", host))
	}
	if !p.Chars.UsesRemovableMedia && (containsAny(t, "removable media", "usb", "portable storage") || containsAny(c, "usb", "removable media")) {
		return na(p, fmt.Sprintf("The %s host does not permit removable media in normal operation.", host))
	}
	if p.Chars.USBStorageDisabled && containsAny(t, "usb storage", "usb mass storage") {
		return naf(p, fmt.Sprintf("USB storage is disabled on the %s host.", host))
	}
	if p.Chars.SeparateTmp && containsAny(t, "/tmp", "temporary file") {
		return naf(p, fmt.Sprintf("The %s host uses a dedicated /tmp mount with controlled options.", host))
	}
	if p.Chars.SeparateVar && strings.Contains(t, "/var") {
		return naf(p, fmt.Sprintf("The %s host uses a dedicated /var mount strategy.", host))
	}
	if p.Chars.SeparateVarLog && containsAny(t, "/var/log", "system log partition") {
		return naf(p, fmt.Sprintf("The %s host uses a dedicated /var/log mount.", host))
	}
	if p.Chars.SeparateVarLogAudit && containsAny(t, "/var/log/audit", "audit log partition") {
		return naf(p, fmt.Sprintf("The %s host uses a dedicated /var/log/audit mount.", host))
	}
	if p.Chars.SeparateVarTmp && containsAny(t, "/var/tmp") {
		return naf(p, fmt.Sprintf("The %s host uses a dedicated /var/tmp mount with controlled options.", host))
	}

	return nr(p, fmt.Sprintf("Rule %s requires host-specific review or an explicit override for the %s profile.", ruleVersion, RHEL9STIGProfileKey))
}
