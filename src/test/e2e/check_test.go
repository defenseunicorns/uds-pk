// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckCommand(t *testing.T) {
	// mock registry API that says only amd64 is available only for testing-dummy:
	srv := mockRepositoryServer()
	t.Cleanup(func() { srv.Close() })

	baseRegistryRepo := srv.URL + "/registry-path"

	// there's no 1.0.0-uds.0-base tag, so we determine it needs a release
	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "check", "base", "-r", baseRegistryRepo, "--verbose", "--plain-http")
	require.NoError(t, err, stdout, stderr)
	require.Contains(t, stderr, "Version is not published version=\"1.0.0-uds.0-base\"")

	// testing-dummy version is published for amd64, no release necessary
	stdout, stderr, err = e2e.UDSPKDir("src/test", "release", "check", "dummy", "-r", baseRegistryRepo, "--verbose", "--plain-http")
	require.Error(t, err, stdout, stderr)
	require.Contains(t, stderr, "no release necessary")

	// testing-dummy version is not published for arm64, but we have a tag
	stdout, stderr, err = e2e.UDSPKDir("src/test", "release", "check", "dummy", "-r", baseRegistryRepo, "--verbose", "--plain-http", "--arch", "arm64")
	require.NoError(t, err, stdout, stderr)
	require.Contains(t, stderr, "Version is not published version=\"testing-dummy\"")

	// so with --skip-publish-check we should determine it doesn't need a release
	stdout, stderr, err = e2e.UDSPKDir("src/test", "release", "check", "dummy", "-r", baseRegistryRepo, "--verbose", "--plain-http", "--arch", "arm64", "--skip-publish-check")
	require.Error(t, err, stdout, stderr)
	require.Contains(t, stderr, "no release necessary")

	stdout, stderr, err = e2e.UDSPKDir("src/test", "release", "check", "-r", baseRegistryRepo, "--verbose", "--plain-http")
	require.NoError(t, err, stdout, stderr)
	require.Contains(t, stderr, "Version is not published version=\"1.0.0-flavorless.0\"")

	// checking version flavorless-testing - should not need a release
	stdout, stderr, err = e2e.UDSPKDir("src/test", "release", "check", "-p", "dummy", "-r", baseRegistryRepo, "--plain-http")
	require.Error(t, err, stdout, stderr)
	require.Contains(t, stderr, "no release necessary")
}

func TestCheckCommandBool(t *testing.T) {
	srv := mockRepositoryServer()
	t.Cleanup(func() { srv.Close() })

	stdout, stderr, err := e2e.UDSPKDir("src/test", "release", "check", "base", "-r", srv.URL+"/registry-path", "--verbose", "--plain-http", "-b")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "true\n", stdout)

	stdout, stderr, err = e2e.UDSPKDir("src/test", "release", "check", "dummy", "-r", srv.URL+"/registry-path", "--verbose", "--plain-http", "-b")
	require.NoError(t, err, stdout, stderr)

	require.Equal(t, "false\n", stdout)
}

func mockRepositoryServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// handle https://<hostname>/v2/<repo path>/manifests/$TAG
		fmt.Println("[http mock] handling" + r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/v2/registry-path/test/manifests/") {
			tag := strings.TrimPrefix(r.URL.Path, "/v2/registry-path/test/manifests/")
			if tag == "testing-dummy" || tag == "flavorless-testing" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
  							"manifests": [
      							{
        							"platform": {
          							"architecture": "amd64"
        							}
      							}
    							]
  							}
  							`))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}
