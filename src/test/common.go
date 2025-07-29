// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	uds "github.com/defenseunicorns/uds-cli/src/types"
	goyaml "github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
	zarf "github.com/zarf-dev/zarf/src/api/v1alpha1"
	"github.com/zarf-dev/zarf/src/pkg/utils/exec"
)

// UDSPKE2ETest Struct holding common fields most of the tests will utilize.
type UDSPKE2ETest struct {
	UDSPKBinPath    string
	Arch            string
	RunClusterTests bool
	CommandLog      []string
}

// GetCLIName looks at the OS and CPU architecture to determine which binary needs to be run.
func GetCLIName() string {
	var binaryName string
	switch runtime.GOOS {
	case "linux":
		binaryName = "uds-pk"
	case "darwin":
		if runtime.GOARCH == "arm64" {
			binaryName = "uds-pk-mac-apple"
		} else {
			binaryName = "uds-pk-mac-intel"
		}
	}
	return binaryName
}

// UDSPK executes a uds-pk command.
func (e2e *UDSPKE2ETest) UDSPK(args ...string) (string, string, error) {
	e2e.CommandLog = append(e2e.CommandLog, strings.Join(args, " "))
	return exec.CmdWithContext(context.TODO(), exec.PrintCfg(), e2e.UDSPKBinPath, args...)
}

// UDSPKDir executes a uds-pk command in a specific directory.
// relativeBinDir is the relative path to the base repo folder from the directory.
func (e2e *UDSPKE2ETest) UDSPKDir(dir string, args ...string) (string, string, error) {
	e2e.CommandLog = append(e2e.CommandLog, strings.Join(args, " "))
	config := exec.PrintCfg()
	config.Dir = dir
	return exec.CmdWithContext(context.TODO(), config, e2e.UDSPKBinPath, args...)
}

func (e2e *UDSPKE2ETest) CreateSandboxDir(t *testing.T, subfolders ...string) {
	// Create a sandbox directory for our tests
	sandboxDir := "src/test/sandbox"
	err := os.Mkdir(sandboxDir, 0o755)

	for _, subfolder := range subfolders {
		err = os.Mkdir(filepath.Join(sandboxDir, subfolder), 0o755)
		require.NoError(t, err)
	}
	require.NoError(t, err)
}

func (e2e *UDSPKE2ETest) CleanupSandboxDir(t *testing.T) {
	// Cleanup the sandbox directory
	sandboxDir := "src/test/sandbox"
	err := os.RemoveAll(sandboxDir)
	require.NoError(t, err)
}

func (e2e *UDSPKE2ETest) CreateZarfYaml(t *testing.T, dir string) {
	// Create a zarf.yaml file for our tests
	var zarfPackage zarf.ZarfPackage
	zarfPackage.Metadata.Name = "testing-package"
	zarfPackage.Metadata.Version = "devel"

	data, err := goyaml.Marshal(zarfPackage)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dir, "zarf.yaml"), data, 0o644)
	require.NoError(t, err)
}

func (e2e *UDSPKE2ETest) CreateAltZarfYaml(t *testing.T, name string, dir string) {
	// Create a zarf.yaml file for our tests
	var zarfPackage zarf.ZarfPackage
	zarfPackage.Metadata.Name = name
	zarfPackage.Metadata.Version = "devel"

	data, err := goyaml.Marshal(zarfPackage)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dir, "zarf.yaml"), data, 0o644)
	require.NoError(t, err)
}

func (e2e *UDSPKE2ETest) CreateUDSBundleYaml(t *testing.T, dir string) {
	// Create a uds-bundle.yaml file for our tests
	var udsBundle uds.UDSBundle
	udsBundle.Metadata.Name = "testing-bundle"
	udsBundle.Metadata.Version = "devel"
	testingPackage := uds.Package{
		Name: "testing-package",
		Ref:  "devel",
	}
	udsBundle.Packages = []uds.Package{testingPackage}

	data, err := goyaml.Marshal(udsBundle)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dir, "uds-bundle.yaml"), data, 0o644)
	require.NoError(t, err)
}

func (e2e *UDSPKE2ETest) CreateUDSBundleYamlMultiPackage(t *testing.T, dir string) {
	// Create a uds-bundle.yaml file for our tests
	var udsBundle uds.UDSBundle
	udsBundle.Metadata.Name = "testing-bundle"
	udsBundle.Metadata.Version = "devel"
	basePackage := uds.Package{
		Name: "testing-package",
		Ref:  "devel",
	}
	firstPackage := uds.Package{
		Name: "first",
		Ref:  "devel",
	}
	secondPackage := uds.Package{
		Name: "second",
		Ref:  "devel",
	}
	udsBundle.Packages = []uds.Package{basePackage, firstPackage, secondPackage}

	data, err := goyaml.Marshal(udsBundle)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dir, "uds-bundle.yaml"), data, 0o644)
	require.NoError(t, err)
}

func (e2e *UDSPKE2ETest) LoadYaml(path string, destVar interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return goyaml.Unmarshal(data, destVar)
}

// CleanFiles removes files and directories that have been created during the test.
func (e2e *UDSPKE2ETest) CleanFiles(files ...string) {
	for _, file := range files {
		_ = os.RemoveAll(file)
	}
}

// GetMismatchedArch determines what architecture our tests are running on,
// and returns the opposite architecture.
func (e2e *UDSPKE2ETest) GetMismatchedArch() string {
	switch e2e.Arch {
	case "arm64":
		return "amd64"
	default:
		return "arm64"
	}
}

// GetUdsVersion returns the current build version
func (e2e *UDSPKE2ETest) GetUdsVersion(t *testing.T) string {
	// Get the version of the CLI
	stdOut, stdErr, err := e2e.UDSPK("version")
	require.NoError(t, err, stdOut, stdErr)
	return strings.Trim(stdOut, "\n")
}

// GetGitRevision returns the current git revision
func (e2e *UDSPKE2ETest) GetGitRevision() (string, error) {
	out, _, err := exec.Cmd("git", "rev-parse", "--short", "HEAD")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out), nil
}
