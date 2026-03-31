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
app_name: test-app
fqdn: test.example.com
description: A test application.
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
`
	err := os.WriteFile(profilePath, []byte(content), 0644)
	require.NoError(t, err)

	profile, err := LoadProfile(profilePath)
	require.NoError(t, err)

	require.Equal(t, "test-app", profile.AppName)
	require.Equal(t, "test.example.com", profile.FQDN)
	require.Equal(t, "A test application.", profile.Description)

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
fqdn: test.example.com
description: No app name.
`
	err := os.WriteFile(profilePath, []byte(content), 0644)
	require.NoError(t, err)

	_, err = LoadProfile(profilePath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "app_name is required")
}
