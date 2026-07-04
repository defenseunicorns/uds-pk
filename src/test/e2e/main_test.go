// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/test"

	"github.com/defenseunicorns/uds-cli/src/config"
)

var (
	e2e test.UDSPKE2ETest //nolint:gochecknoglobals
)

// TestMain lets us customize the test run. See https://medium.com/goingogo/why-use-testmain-for-testing-in-go-dafb52b406bc.
func TestMain(m *testing.M) {
	// Work from the root directory of the project
	err := os.Chdir("../../../")
	if err != nil {
		fmt.Println(err)
	}

	retCode, err := doAllTheThings(m)
	if err != nil {
		fmt.Println(err) //nolint:forbidigo
	}

	os.Exit(retCode)
}

// doAllTheThings just wraps what should go in TestMain. It's in its own function so it can
// [a] Not have a bunch of `os.Exit()` calls in it
// [b] Do defers properly
// [c] Handle errors cleanly
//
// It returns the return code passed from `m.Run()` and any error thrown.
func doAllTheThings(m *testing.M) (int, error) {
	var err error

	// Set up constants in the global variable that all the tests are able to access
	e2e.Arch = config.GetArch()
	e2e.UDSPKBinPath, err = filepath.Abs(path.Join("build", test.GetCLIName()))
	if err != nil {
		return 1, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Validate that the uds-pk binary exists. If it doesn't that means the dev hasn't built it
	_, err = os.Stat(e2e.UDSPKBinPath)
	if err != nil {
		return 1, fmt.Errorf("uds-pk binary %s not found", e2e.UDSPKBinPath)
	}

	// Run the tests, with the cluster cleanup being deferred to the end of the function call
	returnCode := m.Run()

	isCi := os.Getenv("CI") == "true"
	if isCi {
		fmt.Println("::notice::uds-pk Command Log")
		// Print out the command history
		fmt.Println("::group::uds-pk Command Log")
		for _, cmd := range e2e.CommandLog {
			fmt.Println(cmd) // todo: it's a UDS cmd but this links up with pterm in Zarf
		}
		fmt.Println("::endgroup::")
	}

	return returnCode, nil
}
