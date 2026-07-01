// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadProfile_Success(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "stig-profile.yaml")
content := `
kind: UDS STIG Profile
metadata:
  name: test-app
  description: A test application.
  version: 0.1.0
stigs:
  - id: asd_v6r4
    description: ASD STIG
    characteristics:
      uses_soap: false
      uses_saml: true
      uses_database: true
      is_stateless: false
      has_user_input: true
      language: go
    platform:
      auth_provider: Keycloak
      auth_proxy: authservice
      service_mesh: Istio
      container_runtime: Kubernetes
      network_policies: true
      cicd_sast: Semgrep
    overrides:
      APSC-DV-000010:
        status: not_a_finding
        finding_details: Custom details.
        comments: Custom comment.
  - id: rhel9_v2r7
    description: RHEL 9 STIG
`
	err := os.WriteFile(profilePath, []byte(content), 0644)
	require.NoError(t, err)

	profile, err := LoadProfile(profilePath)
	require.NoError(t, err)

	require.Equal(t, ProfileKind, profile.Kind)
	require.Equal(t, "test-app", profile.AppName)
	require.Empty(t, profile.FQDN)
	require.Equal(t, "A test application.", profile.Description)
	require.NotNil(t, profile.SelectedSTIG)
	require.Equal(t, ASDSTIGProfileKey, profile.SelectedSTIG.ID)

	// Characteristics
	require.False(t, profile.Chars.UsesSOAP)
	require.True(t, profile.Chars.UsesSAML)
	require.True(t, profile.Chars.UsesDatabase)
	require.False(t, profile.Chars.IsStateless)
	require.True(t, profile.Chars.HasUserInput)
	require.Equal(t, "go", profile.Chars.Language)

	// Platform
	require.Equal(t, "Keycloak", profile.Platform.AuthProvider)
	require.Equal(t, "authservice", profile.Platform.AuthProxy)
	require.Equal(t, "Istio", profile.Platform.ServiceMesh)
	require.True(t, profile.Platform.NetworkPolicies)
	require.Equal(t, "Semgrep", profile.Platform.CICD_SAST)

	// Overrides
	require.Len(t, profile.Overrides, 1)
	ov := profile.Overrides["APSC-DV-000010"]
	require.Equal(t, "not_a_finding", ov.Status)
	require.Equal(t, "Custom details.", ov.FindingDetails)
	require.Equal(t, "Custom comment.", ov.Comments)
}

func TestLoadProfile_SelectsFirstSupportedSTIG(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "rhel-first-profile.yaml")
	content := `
kind: UDS STIG Profile
metadata:
  name: test-rhel9-host
  description: A test RHEL 9 host.
  version: 0.1.0
stigs:
  - id: rhel9_v2r7
    description: RHEL 9 STIG
    characteristics:
      has_gui: false
      uses_selinux: true
    platform:
      os_name: Red Hat Enterprise Linux 9
      host_role: Standalone Kubernetes server
  - id: asd_v6r4
    description: ASD STIG
`
	err := os.WriteFile(profilePath, []byte(content), 0644)
	require.NoError(t, err)

	profile, err := LoadProfile(profilePath)
	require.NoError(t, err)
	require.NotNil(t, profile.SelectedSTIG)
	require.Equal(t, RHEL9STIGProfileKey, profile.SelectedSTIG.ID)
	require.False(t, profile.Chars.HasGUI)
	require.True(t, profile.Chars.UsesSELinux)
	require.Equal(t, "Red Hat Enterprise Linux 9", profile.Platform.OSName)
	require.Equal(t, "Standalone Kubernetes server", profile.Platform.HostRole)
}

func TestLoadProfile_FileNotFound(t *testing.T) {
	_, err := LoadProfile("/nonexistent/profile.yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "reading")
}

func TestLoadProfile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "bad.yaml")
	err := os.WriteFile(profilePath, []byte(":\n  :\n  - {["), 0644)
	require.NoError(t, err)

	_, err = LoadProfile(profilePath)
	require.Error(t, err)
}

func TestLoadProfile_MissingAppName(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "no-name.yaml")
content := `
kind: UDS STIG Profile
metadata:
  description: No app name.
  version: 0.1.0
stigs:
  - id: rhel9_v2r7
    description: RHEL 9 STIG
`
	err := os.WriteFile(profilePath, []byte(content), 0644)
	require.NoError(t, err)

	_, err = LoadProfile(profilePath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "metadata.name is required")
}
