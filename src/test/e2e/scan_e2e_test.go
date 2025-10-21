// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/cmd"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/google/go-github/v73/github"
	"github.com/spf13/cobra"
)

func simulateGrype(args []string, stdout io.Writer, stderr io.Writer) {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	program := args[0]
	if program != "grype" {
		panic("simulateGrype only supports grype: " + program)
	}

	if len(args) < 2 {
		panic("grype requires a command")
	}

	command := args[1]

	switch command {
	case "db":
		if len(args) < 3 {
			panic("grype db requires a subcommand")
		}
		subcommand := args[2]
		switch subcommand {
		case "status":
			{ // grype db status
				// print healthy status
				_, _ = fmt.Fprint(stdout, "ok\n")
				return
			}
		case "update":
			{ // grype db update
				// print healthy status
				_, _ = fmt.Fprint(stdout, "ok\n")
				return
			}
		}
	default:
		{
			// in the default mode - we're scanning. The file to scan is a positional argument
			// after the command.
			var outFile string
			var output string

			grypeFlagSet := flag.NewFlagSet("grype", flag.ContinueOnError)
			grypeFlagSet.StringVar(&outFile, "file", "default-file.json", "")
			grypeFlagSet.Bool("add-cpes-if-none", false, "")
			grypeFlagSet.StringVar(&output, "output", "", "")
			grypeFlagSet.Bool("v", false, "")
			err := grypeFlagSet.Parse(args[1:])
			if err != nil {
				panic("failed to parse grype args: " + err.Error())
			}
			jsonFile := grypeFlagSet.Arg(0)

			var vulns []map[string]any
			if !strings.HasPrefix(jsonFile, "sbom:") {
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
			f, err := os.Create(outFile)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "failed to open file[%s] for writing: %v\n", outFile, err)
				return
			}
			if err := json.NewEncoder(f).Encode(payload); err != nil {
				_, _ = fmt.Fprintf(stderr, "failed to write JSON: %v\n", err)
				_, _ = fmt.Fprintln(stderr, err)
				_ = f.Close()
				return
			} else {
				_, _ = fmt.Fprintf(stderr, "writen JSON to %s\n", outFile)
			}
			if err := f.Close(); err != nil {
				_, _ = fmt.Fprintln(stderr, err)
			}
			return

		}
	}
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
	simulateGrype(append([]string{f.cmd}, f.args...), out, err)
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

func fakeExecCommand(command string, args ...string) utils.CommandRunner {
	return &FakeCommand{cmd: command, args: args}
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
	log := cmd.CreateLogger(true)

	tmp := t.TempDir()
	outputDirectory := filepath.Join(tmp, "out")
	scanOptions := cmd.CommonScanOptions{}
	scanOptions.ZarfYamlLocation = writeZarfYaml(t, tmp)
	scanOptions.ExecCommand = fakeExecCommand

	res, err := cmd.ScanZarfYamlImages(outputDirectory, &scanOptions, log, true)
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
	log := cmd.CreateLogger(true)

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

	scanReleasedOptions := cmd.ScanReleasedOptions{}

	scanReleasedOptions.Scan.ZarfYamlLocation = writeZarfYaml(t, tmp)
	scanReleasedOptions.Scan.ExecCommand = fakeExecCommand
	outDir := filepath.Join(tmp, "out")

	res, err := cmd.ScanReleased(outDir, &scanReleasedOptions, log, true)
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
	options := cmd.ScanAndCompareOptions{}
	// Apply image name override so elasticsearch-exporter matches elasticsearch released scan
	options.ImageNameOverrides = []string{"elasticsearch=elasticsearch-exporter"}

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
	outFile := filepath.Join(tmp, "compare.md")
	options.Scan.Scan.ZarfYamlLocation = writeZarfYaml(t, tmp)
	options.Scan.Scan.OutputDirectory = filepath.Join(tmp, "out")
	options.Scan.Scan.ExecCommand = fakeExecCommand
	options.ScanAndCompareOutputFile = outFile

	ctx := context.Background()
	command := &cobra.Command{}
	ctx = cmd.InitLoggerContext(true, ctx)
	command.SetContext(ctx)
	err := options.Run(command, []string{})
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

	origNewGH := cmd.NewGithubClient
	cmd.NewGithubClient = func(_ *context.Context) *github.Client {
		c := github.NewClient(srv.Client())
		u, _ := url.Parse(srv.URL + "/")
		c.BaseURL = u
		return c
	}
	t.Cleanup(func() { cmd.NewGithubClient = origNewGH })
}

// withMockFetchSboms overrides the package-level FetchSboms for the duration
// of a test and restores it automatically via t.Cleanup.
func withMockFetchSboms(t *testing.T, fn func(repoOwner, packageUrl, tag string, outputDir string, logger *slog.Logger) ([]string, error)) {
	t.Helper()
	orig := cmd.FetchSboms
	cmd.FetchSboms = fn
	t.Cleanup(func() { cmd.FetchSboms = orig })
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
