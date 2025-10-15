// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/scan"
	"github.com/google/go-github/v73/github"
)

func simulateGrype(args []string, stdout io.Writer, stderr io.Writer) {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep == -1 || sep+1 >= len(args) {
		_, _ = fmt.Fprintln(stderr, "invalid simulateGrype")
		return
	}
	cmd := args[sep+1]
	cmdArgs := args[sep+2:]

	if cmd == "grype" {
		// emulate different subcommands
		if len(cmdArgs) >= 2 && cmdArgs[0] == "db" && cmdArgs[1] == "status" {
			// print healthy status
			_, _ = fmt.Fprint(stdout, "ok\n")
			return
		}
		if len(cmdArgs) >= 2 && cmdArgs[0] == "db" && cmdArgs[1] == "update" {
			return
		}
		// normal scan: find --file path and write minimal CycloneDX JSON
		var outPath string
		for i := 0; i < len(cmdArgs)-1; i++ {
			if cmdArgs[i] == "--file" {
				outPath = cmdArgs[i+1]
				break
			}
		}
		if outPath == "" {
			_, _ = fmt.Fprintln(stderr, "--file not provided")
			return
		}
		// Decide whether this is an SBOM scan to vary vulnerabilities
		isSBOM := false
		for _, a := range cmdArgs {
			if strings.HasPrefix(a, "sbom:") {
				isSBOM = true
				break
			}
		}
		vulns := []map[string]any{}
		if !isSBOM {
			vulns = []map[string]any{
				{
					"id":         "CVE-TEST-1",
					"source":     map[string]any{"url": "https://example.com/CVE-TEST-1"},
					"advisories": []map[string]any{{"url": "https://adv.example/CVE-TEST-1"}},
					"ratings":    []map[string]any{{"severity": "high"}},
					"affects":    []map[string]any{{"ref": "pkg:apk/alpine/busybox@1.36.1"}},
				},
			}
		}
		// minimal CycloneDX structure required by compare code
		payload := map[string]any{
			"metadata": map[string]any{
				"component": map[string]any{
					"name":    "elasticsearch-exporter",
					"version": "1.9.0",
				},
			},
			"vulnerabilities": vulns,
		}
		f, err := os.Create(outPath)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return
		}
		if err := json.NewEncoder(f).Encode(payload); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			_ = f.Close()
			return
		}
		if err := f.Close(); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
		}
		return
	}
	_, _ = fmt.Fprintln(stderr, "unknown command")
}

// FakeCommand simulates a command for testing purposes
type FakeCommand struct {
	cmd    string
	args   []string
	stdout io.Writer
	stderr io.Writer
}

func (f *FakeCommand) Run() error {
	out := f.stdout
	if out == nil {
		out = io.Discard
	}
	err := f.stderr
	if err == nil {
		err = io.Discard
	}
	simulateGrype(append([]string{"--", f.cmd}, f.args...), out, err)
	return nil
}

func (f *FakeCommand) SetStdout(stdout io.Writer) {
	f.stdout = stdout
}

func (f *FakeCommand) SetStderr(stderr io.Writer) {
	f.stderr = stderr
}

func (f *FakeCommand) CombinedOutput() ([]byte, error) {
	var buf bytes.Buffer
	simulateGrype(append([]string{"--", f.cmd}, f.args...), &buf, &buf)
	return buf.Bytes(), nil
}

func fakeExecCommand(command string, args ...string) scan.CommandRunner {
	return &FakeCommand{cmd: command, args: args}
}

func setupLogger() {
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func writeZarfYaml(t *testing.T, dir string) string {
	t.Helper()
	content := `metadata:
  name: elasticsearch
components:
  - name: c1
    only:
      flavor: registry1
    images:
      - example.com/opensource/bitnami/elasticsearch-exporter:1.9.0
`
	p := filepath.Join(dir, "zarf.yaml")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanCommand_EndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("exec helper pattern may not work on this OS")
	}
	setupLogger()
	origExec := scan.ExecCommand
	scan.ExecCommand = fakeExecCommand
	defer func() { scan.ExecCommand = origExec }()

	tmp := t.TempDir()
	zarfYamlLocation = writeZarfYaml(t, tmp)
	outputDirectory = filepath.Join(tmp, "out")

	res, err := scanZarfYamlImages(outputDirectory)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	// Expect one flavor and one file
	files := res["registry1"]
	if len(files) != 1 {
		t.Fatalf("expected 1 scan result, got %d", len(files))
	}
	var path string
	for _, p := range files {
		path = p
	}
	if !strings.HasSuffix(path, "/registry1/elasticsearch-exporter_1.9.0.json") {
		t.Fatalf("unexpected output path: %s", path)
	}
	// validate JSON exists and contains metadata.component
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read output: %v", err)
	}
	if !strings.Contains(string(data), "\"metadata\"") {
		t.Fatalf("output not JSON-like: %s", string(data))
	}
}

func TestScanReleased_EndToEnd(t *testing.T) {
	setupLogger()
	origExec := scan.ExecCommand
	scan.ExecCommand = fakeExecCommand
	defer func() { scan.ExecCommand = origExec }()

	// Mock GitHub API with helper
	withMockGitHub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1, "metadata": {"container": {"tags": ["8.16.0-registry1"]}}}]`))
			return
		}
		if strings.Contains(r.URL.Path, "/orgs/") && strings.Contains(r.URL.Path, "/packages/container/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	withMockFetchSbomsUserInput(t, "elasticsearch_8.16.0.json", "docker:example.com/opensource/bitnami/elasticsearch:8.16.0")

	tmp := t.TempDir()
	zarfYamlLocation = writeZarfYaml(t, tmp)
	outDir := filepath.Join(tmp, "out")

	res, err := scanReleased(outDir)
	if err != nil {
		t.Fatalf("scan-released failed: %v", err)
	}
	files := res["registry1"]
	if len(files) != 1 {
		t.Fatalf("expected 1 released scan result, got %d", len(files))
	}
	var p string
	for _, v := range files {
		p = v
	}
	if !strings.HasSuffix(p, "/registry1/elasticsearch_8.16.0.json") {
		t.Fatalf("unexpected released output path: %s", p)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("released output file missing: %v", err)
	}
}

func TestScanAndCompare_EndToEnd(t *testing.T) {
	setupLogger()
	origExec := scan.ExecCommand
	scan.ExecCommand = fakeExecCommand
	defer func() { scan.ExecCommand = origExec }()

	// Apply image name override so elasticsearch-exporter matches elasticsearch released scan
	origOverrides := imageNameOverrides
	imageNameOverrides = []string{"elasticsearch=elasticsearch-exporter"}
	defer func() { imageNameOverrides = origOverrides }()

	// Mock GitHub API with helper
	withMockGitHub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1, "metadata": {"container": {"tags": ["8.16.0-registry1"]}}}]`))
			return
		}
		if strings.Contains(r.URL.Path, "/orgs/") && strings.Contains(r.URL.Path, "/packages/container/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	withMockFetchSbomsUserInput(t, "elasticsearch_8.16.0.json", "docker:example.com/opensource/bitnami/elasticsearch:8.16.0")

	tmp := t.TempDir()
	zarfYamlLocation = writeZarfYaml(t, tmp)
	outputDirectory = filepath.Join(tmp, "out")

	// Use --output to write markdown to a file
	outFile := filepath.Join(tmp, "compare.md")
	if err := scanAndCompareCmd.Flags().Set("output", outFile); err != nil {
		t.Fatalf("failed to set output flag: %v", err)
	}
	defer func() { _ = scanAndCompareCmd.Flags().Set("output", "") }()

	err := scanAndCompareCmd.RunE(scanAndCompareCmd, []string{})
	if err != nil {
		t.Fatalf("scan-and-compare failed: %v", err)
	}

	b, rerr := os.ReadFile(outFile)
	if rerr != nil {
		t.Fatalf("failed to read output file: %v", rerr)
	}
	out := string(b)

	if !strings.Contains(out, "New vulnerabilities: 1") {
		t.Fatalf("expected one new vulnerability, got output: %s", out)
	}
	if !strings.Contains(out, "Fixed vulnerabilities: 0") {
		t.Fatalf("expected zero fixed vulnerabilities, got output: %s", out)
	}
}

// withMockGitHub starts a test HTTP server with the given handler and
// overrides NewGithubClient to point to it. Cleanup is automatic via t.Cleanup.
func withMockGitHub(t *testing.T, handler http.Handler) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(func() { srv.Close() })

	origNewGH := NewGithubClient
	NewGithubClient = func(_ *context.Context) *github.Client {
		c := github.NewClient(srv.Client())
		u, _ := url.Parse(srv.URL + "/")
		c.BaseURL = u
		return c
	}
	t.Cleanup(func() { NewGithubClient = origNewGH })
}

// withMockFetchSboms overrides the package-level FetchSboms for the duration
// of a test and restores it automatically via t.Cleanup.
func withMockFetchSboms(t *testing.T, fn func(repoOwner, packageUrl, tag string, outputDir string, logger *slog.Logger) ([]string, error)) {
	t.Helper()
	orig := FetchSboms
	FetchSboms = fn
	t.Cleanup(func() { FetchSboms = orig })
}

// withMockFetchSbomsUserInput writes a minimal SBOM JSON to outputDir/fileName
// with the provided source.metadata.userInput and returns that path.
func withMockFetchSbomsUserInput(t *testing.T, fileName, userInput string) {
	t.Helper()
	withMockFetchSboms(t, func(_ string, _ string, _ string, outDir string, _ *slog.Logger) ([]string, error) {
		p := filepath.Join(outDir, fileName)
		sbom := map[string]any{"source": map[string]any{"metadata": map[string]any{"userInput": userInput}}}
		f, err := os.Create(p)
		if err != nil {
			return nil, err
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)
		if err := json.NewEncoder(f).Encode(sbom); err != nil {
			return nil, err
		}
		return []string{p}, nil
	})
}
