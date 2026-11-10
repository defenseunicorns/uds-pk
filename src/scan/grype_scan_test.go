// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package scan_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/scan"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/stretchr/testify/require"
)

type registryTransport func(*http.Request) (*http.Response, error)

func (f registryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fixtureScan struct{ run func() error }

func (f *fixtureScan) Run() error                      { return f.run() }
func (f *fixtureScan) CombinedOutput() ([]byte, error) { return nil, f.run() }
func (f *fixtureScan) SetStdout(io.Writer)             {}
func (f *fixtureScan) SetStderr(io.Writer)             {}

func TestDownloadedPlatformSBOMsKeepSeparateScanResults(t *testing.T) {
	for _, includePlatform := range []bool{true, false} {
		t.Run(fmt.Sprintf("platformMetadata=%t", includePlatform), func(t *testing.T) {
			responses := map[string][]byte{}
			manifest := utils.ImageManifest{}
			for _, arch := range []string{"amd64", "arm64"} {
				metadata := map[string]string{"userInput": "example.com/app:v1"}
				if includePlatform {
					metadata["architecture"] = arch
					metadata["os"] = "linux"
				}
				data, err := json.Marshal(map[string]any{"source": map[string]any{"metadata": metadata}, "fixtureFinding": "CVE-" + arch})
				require.NoError(t, err)
				digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
				title := "sboms/images/" + base64.RawURLEncoding.EncodeToString([]byte("example.com/app:v1-linux-"+arch)) + ".json"
				manifest.Layers = append(manifest.Layers, utils.Layer{MediaType: "application/vnd.syft+json", Digest: digest,
					Annotations: map[string]string{"org.opencontainers.image.title": title, "dev.zarf.resource.kind": "sbom"}})
				responses["blobs/"+digest] = data
			}
			manifestData, err := json.Marshal(manifest)
			require.NoError(t, err)
			responses["manifests/v1"] = manifestData
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			http.DefaultTransport = registryTransport(func(r *http.Request) (*http.Response, error) {
				data, found := responses[strings.TrimPrefix(r.URL.Path, "/v2/test/app/")]
				require.True(t, found, "unexpected request %s", r.URL)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}}, nil
			})
			dir := t.TempDir()
			sbomDir := filepath.Join(dir, "sboms")
			files, err := utils.FetchSboms("test", "app", "v1", sbomDir, slog.Default())
			require.NoError(t, err)
			require.Len(t, files, 2)
			runner := func(command string, args ...string) utils.CommandRunner {
				require.Equal(t, "grype", command)
				return &fixtureScan{run: func() error {
					var output string
					for i, arg := range args {
						if arg == "--file" {
							output = args[i+1]
						}
					}
					data, err := os.ReadFile(strings.TrimPrefix(args[len(args)-1], "sbom:"))
					if err != nil {
						return err
					}
					var fixture struct {
						Finding string `json:"fixtureFinding"`
					}
					if err := json.Unmarshal(data, &fixture); err != nil {
						return err
					}
					return os.WriteFile(output, []byte(fixture.Finding), 0o600)
				}}
			}
			outputDir := filepath.Join(dir, "scans")
			results, err := scan.SBOMs(sbomDir, outputDir, slog.Default(), false, runner)
			require.NoError(t, err)
			require.Len(t, results, 2)
			var findings []string
			for _, output := range results {
				data, err := os.ReadFile(output)
				require.NoError(t, err)
				findings = append(findings, string(data))
			}
			require.ElementsMatch(t, []string{"CVE-amd64", "CVE-arm64"}, findings)
			outputs, err := filepath.Glob(filepath.Join(outputDir, "*.json"))
			require.NoError(t, err)
			require.Len(t, outputs, 2)
		})
	}
}
