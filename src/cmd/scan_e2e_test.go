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

// helperProcessLogic contains the core logic for simulating external commands
func helperProcessLogic(args []string, stdout io.Writer, stderr io.Writer) {
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
		fmt.Fprintln(stderr, "invalid helper invocation")
		return
	}
	cmd := args[sep+1]
	cmdArgs := args[sep+2:]

	if cmd == "grype" {
		// emulate different subcommands
		if len(cmdArgs) >= 2 && cmdArgs[0] == "db" && cmdArgs[1] == "status" {
			// print healthy status
			fmt.Fprint(stdout, "ok\n")
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
			fmt.Fprintln(stderr, "--file not provided")
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
			fmt.Fprintln(stderr, err)
			return
		}
		_ = json.NewEncoder(f).Encode(payload)
		_ = f.Close()
		return
	}
	fmt.Fprintln(stderr, "unknown command")
	return
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
	helperProcessLogic(append([]string{"--", f.cmd}, f.args...), out, err)
	return nil
}

func (f *FakeCommand) SetStdout(stdout *os.File) {
	f.stdout = stdout
}

func (f *FakeCommand) SetStderr(stderr *os.File) {
	f.stderr = stderr
}

// Add CombinedOutput method to FakeCommand
func (f *FakeCommand) CombinedOutput() ([]byte, error) {
	var buf bytes.Buffer
	helperProcessLogic(append([]string{"--", f.cmd}, f.args...), &buf, &buf)
	return buf.Bytes(), nil
}

// substitute ExecCommand for tests
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
      - registry1.dso.mil/ironbank/opensource/bitnami/elasticsearch-exporter:1.9.0
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

	// Mock GitHub API with httptest server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer srv.Close()

	origNewGH := NewGithubClient
	NewGithubClient = func(_ *context.Context) *github.Client {
		c := github.NewClient(srv.Client())
		// Override BaseURL to test server
		u, _ := url.Parse(srv.URL + "/")
		c.BaseURL = u
		return c
	}
	defer func() { NewGithubClient = origNewGH }()

	// Mock SBOM fetcher to write a minimal SBOM to outputDir and return its path
	origFetch := FetchSboms
	FetchSboms = func(_ string, _ string, _ string, outDir string, _ *slog.Logger) ([]string, error) {
		p := filepath.Join(outDir, "elasticsearch_8.16.0.json")
		// SBOM with userInput to drive scanSBOM naming
		sbom := map[string]any{"source": map[string]any{"metadata": map[string]any{"userInput": "docker:registry1.dso.mil/ironbank/opensource/bitnami/elasticsearch:8.16.0"}}}
		f, err := os.Create(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err := json.NewEncoder(f).Encode(sbom); err != nil {
			return nil, err
		}
		return []string{p}, nil
	}
	defer func() { FetchSboms = origFetch }()

	tmp := t.TempDir()
	// zarf.yaml with flavor, images can be empty for released path but keep consistent
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

	// Mock GitHub API
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer srv.Close()

	origNewGH := NewGithubClient
	NewGithubClient = func(_ *context.Context) *github.Client {
		c := github.NewClient(srv.Client())
		u, _ := url.Parse(srv.URL + "/")
		c.BaseURL = u
		return c
	}
	defer func() { NewGithubClient = origNewGH }()

	origFetch := FetchSboms
	FetchSboms = func(_ string, _ string, _ string, outDir string, _ *slog.Logger) ([]string, error) {
		p := filepath.Join(outDir, "elasticsearch_8.16.0.json")
		sbom := map[string]any{"source": map[string]any{"metadata": map[string]any{"userInput": "docker:registry1.dso.mil/ironbank/opensource/bitnami/elasticsearch:8.16.0"}}}
		f, err := os.Create(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err := json.NewEncoder(f).Encode(sbom); err != nil {
			return nil, err
		}
		return []string{p}, nil
	}
	defer func() { FetchSboms = origFetch }()

	tmp := t.TempDir()
	zarfYamlLocation = writeZarfYaml(t, tmp)
	outputDirectory = filepath.Join(tmp, "out")

	// capture stdout
	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := scanAndCompareCmd.RunE(scanAndCompareCmd, []string{})
	w.Close()
	os.Stdout = origStdout
	if err != nil {
		t.Fatalf("scan-and-compare failed: %v", err)
	}
	b, _ := io.ReadAll(r)
	out := string(b)

	if !strings.Contains(out, "New vulnerabilities: 1") {
		t.Fatalf("expected one new vulnerability, got output: %s", out)
	}
	if !strings.Contains(out, "Fixed vulnerabilities: 0") {
		t.Fatalf("expected zero fixed vulnerabilities, got output: %s", out)
	}
}
