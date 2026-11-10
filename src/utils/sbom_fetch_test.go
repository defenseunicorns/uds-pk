// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type sbomTransport func(*http.Request) (*http.Response, error)

func (f sbomTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockSBOMRegistry(t *testing.T, responses map[string][]byte) {
	t.Helper()
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = sbomTransport(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, "ghcr.io", r.URL.Host)
		key := strings.TrimPrefix(r.URL.Path, "/v2/test/app/")
		data, ok := responses[key]
		if !ok {
			t.Errorf("unexpected registry request: %s", key)
			return nil, fmt.Errorf("unexpected request %s", key)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}}, nil
	})
}

func TestFetchSbomsBothLayouts(t *testing.T) {
	const imageSBOM = `{"source":{"metadata":{"userInput":"example.com/app:v1"}}}`
	const componentSBOM = `{"source":{"type":"directory"}}`
	for _, beta := range []bool{false, true} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("beta=%t/index=%t", beta, indexed), func(t *testing.T) {
				responses := map[string][]byte{}
				manifest := ImageManifest{}
				if beta {
					for title, content := range map[string]string{
						"sboms/images/encoded-image.json": imageSBOM,
						"sboms/files/app.json":            componentSBOM,
					} {
						digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content)))
						manifest.Layers = append(manifest.Layers, Layer{MediaType: "application/vnd.syft+json", Digest: digest, Annotations: map[string]string{
							"org.opencontainers.image.title": title, "dev.zarf.resource.kind": "sbom",
						}})
						responses["blobs/"+digest] = []byte(content)
					}
					// Attachments with JSON contents must not be scanned as SBOMs.
					manifest.Layers = append(manifest.Layers, Layer{Digest: "attachment", Annotations: map[string]string{"org.opencontainers.image.title": "attachments/notes.json"}})
				} else {
					var archive bytes.Buffer
					writer := tar.NewWriter(&archive)
					for title, content := range map[string]string{"nested/app.json": imageSBOM, "component.json": componentSBOM, "ignore.txt": "not a SBOM"} {
						require.NoError(t, writer.WriteHeader(&tar.Header{Name: title, Mode: 0o644, Size: int64(len(content))}))
						_, err := writer.Write([]byte(content))
						require.NoError(t, err)
					}
					require.NoError(t, writer.Close())
					manifest.Layers = []Layer{{Digest: "archive", Annotations: map[string]string{"org.opencontainers.image.title": "sboms.tar"}}}
					responses["blobs/archive"] = archive.Bytes()
				}
				manifestData, err := json.Marshal(manifest)
				require.NoError(t, err)
				if indexed {
					responses["manifests/v1"] = []byte(`{"manifests":[{"digest":"sha256:package"}]}`)
					responses["manifests/sha256:package"] = manifestData
				} else {
					responses["manifests/v1"] = manifestData
				}
				mockSBOMRegistry(t, responses)
				outDir := filepath.Join(t.TempDir(), "sboms")
				files, err := FetchSboms("test", "app", "v1", outDir, slog.Default())
				require.NoError(t, err)
				require.Len(t, files, 2)
				var contents []string
				for _, file := range files {
					require.Equal(t, outDir, filepath.Dir(file))
					data, err := os.ReadFile(file)
					require.NoError(t, err)
					contents = append(contents, string(data))
				}
				require.ElementsMatch(t, []string{imageSBOM, componentSBOM}, contents)
			})
		}
	}
}

func TestFetchSbomsInvalidLayers(t *testing.T) {
	for _, test := range []struct {
		name     string
		manifest string
		blob     string
		err      string
	}{
		{name: "no SBOM", manifest: `{"layers":[]}`, err: "no SBOMs"},
		{name: "empty index", manifest: `{"manifests":[]}`, err: "no manifests"},
		{name: "digest mismatch", manifest: `{"layers":[{"digest":"bad","mediaType":"application/vnd.syft+json","annotations":{"dev.zarf.resource.kind":"sbom","org.opencontainers.image.title":"sboms/files/app.json"}}]}`, blob: `{}`, err: "digest mismatch"},
		{name: "wrong media type", manifest: `{"layers":[{"digest":"bad","mediaType":"text/plain","annotations":{"dev.zarf.resource.kind":"sbom","org.opencontainers.image.title":"sboms/files/app.json"}}]}`, err: "invalid Zarf SBOM"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mockSBOMRegistry(t, map[string][]byte{"manifests/v1": []byte(test.manifest), "blobs/bad": []byte(test.blob)})
			_, err := FetchSboms("test", "app", "v1", t.TempDir(), slog.Default())
			require.ErrorContains(t, err, test.err)
		})
	}
}

func TestWriteSBOMRejectsCollisions(t *testing.T) {
	dir := t.TempDir()
	_, err := writeSBOM(dir, "same.json", strings.NewReader(`{"first":true}`))
	require.NoError(t, err)
	_, err = writeSBOM(dir, "same.json", strings.NewReader(`{"first":false}`))
	require.Error(t, err)
	data, err := os.ReadFile(filepath.Join(dir, "same.json"))
	require.NoError(t, err)
	require.Equal(t, `{"first":true}`, string(data))
}
