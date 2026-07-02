// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveXCCDFPath_UsesExplicitPath(t *testing.T) {
	path, cleanup, err := ResolveXCCDFPath(context.Background(), &Profile{}, "/tmp/test-xccdf.xml")
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.Equal(t, "/tmp/test-xccdf.xml", path)
}

func TestResolveXCCDFPath_DownloadsASDFromZip(t *testing.T) {
	zipBytes := buildTestZip(t, map[string]string{
		"nested/U_ASD_V6R4_Manual_STIG/U_ASD_STIG_V6R4_Manual-xccdf.xml": "<Benchmark></Benchmark>",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer server.Close()

	originalClient := xccdfHTTPClient
	originalDef := stigDefinitions[ASDSTIGProfileKey]
	xccdfHTTPClient = server.Client()
	def := stigDefinitions[ASDSTIGProfileKey]
	def.ZipURL = server.URL
	stigDefinitions[ASDSTIGProfileKey] = def
	t.Cleanup(func() {
		xccdfHTTPClient = originalClient
		stigDefinitions[ASDSTIGProfileKey] = originalDef
	})

	profile := &Profile{
		SelectedSTIG: &STIGProfile{ID: ASDSTIGProfileKey},
	}

	resolvedPath, resolvedCleanup, err := ResolveXCCDFPath(context.Background(), profile, "")
	require.NoError(t, err)
	defer resolvedCleanup()
	require.FileExists(t, resolvedPath)
	data, err := os.ReadFile(resolvedPath)
	require.NoError(t, err)
	require.Equal(t, "<Benchmark></Benchmark>", string(data))
}

func TestResolveXCCDFPath_DownloadsRHEL9FromZip(t *testing.T) {
	zipBytes := buildTestZip(t, map[string]string{
		"nested/U_RHEL_9_V2R7_STIG/U_RHEL_9_STIG_V2R7_Manual-xccdf.xml": "<Benchmark id=\"RHEL\"></Benchmark>",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer server.Close()

	originalClient := xccdfHTTPClient
	originalDef := stigDefinitions[RHEL9STIGProfileKey]
	xccdfHTTPClient = server.Client()
	def := stigDefinitions[RHEL9STIGProfileKey]
	def.ZipURL = server.URL
	stigDefinitions[RHEL9STIGProfileKey] = def
	t.Cleanup(func() {
		xccdfHTTPClient = originalClient
		stigDefinitions[RHEL9STIGProfileKey] = originalDef
	})

	profile := &Profile{
		SelectedSTIG: &STIGProfile{ID: RHEL9STIGProfileKey},
	}

	resolvedPath, resolvedCleanup, err := ResolveXCCDFPath(context.Background(), profile, "")
	require.NoError(t, err)
	defer resolvedCleanup()
	require.FileExists(t, resolvedPath)
	data, err := os.ReadFile(resolvedPath)
	require.NoError(t, err)
	require.Equal(t, "<Benchmark id=\"RHEL\"></Benchmark>", string(data))
}

func TestResolveXCCDFPath_NoSupportedSTIG(t *testing.T) {
	_, cleanup, err := ResolveXCCDFPath(context.Background(), &Profile{}, "")
	t.Cleanup(cleanup)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no supported STIG found")
}

func buildTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "test.zip")

	f, err := os.Create(zipPath)
	require.NoError(t, err)

	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())

	data, err := os.ReadFile(zipPath)
	require.NoError(t, err)
	return data
}
