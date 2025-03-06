// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/zarf-dev/zarf/src/pkg/message"
	"gopkg.in/yaml.v3"
)

// ==========================================================
// Constants and Types
// ==========================================================

const NamespaceExpression = ".components[0].charts[0].namespace"
const WarningSymbol = '⚠'
const ErrorSymbol = '❌'
const SuccessSymbol = '✅'

// CheckResults holds errors, warnings, and successes from verification checks.
type CheckResults struct {
	Errors    []string
	Warnings  []string
	Successes []string
}

// ==========================================================
//  Main Verification Functions
// ==========================================================

// Merge appends the Errors, Warnings, and Successes from another CheckResults instance into this one.
func (r *CheckResults) Merge(other CheckResults) {
	r.Errors = append(r.Errors, other.Errors...)
	r.Warnings = append(r.Warnings, other.Warnings...)
	r.Successes = append(r.Successes, other.Successes...)
}

// VerifyBadge validates a Zarf package in the provided baseDir by checking for manifests and flavors,
// logging the results, and returning an error if any critical issues are found.
func VerifyBadge(baseDir string) error {
	var allResults CheckResults
	var results CheckResults

	commonZarfPath := filepath.Join(baseDir, "common/zarf.yaml")
	rootZarfPath := filepath.Join(baseDir, "zarf.yaml")
	commonZarfYamlExists := fileExists(commonZarfPath)
	codeOwnersPath := filepath.Join(baseDir, "CODEOWNERS")
	testsDir := filepath.Join(baseDir, "tests")
	testsYamlPath := filepath.Join(baseDir, "tasks/test.yaml")
	udsValuesPath := filepath.Join(baseDir, "chart/values.yaml")
	udsPackagePath := filepath.Join(baseDir, "chart/tempates/uds-package.yaml")

	packageName, err := utils.EvaluateYqToString(".metadata.name", rootZarfPath)
	if err != nil {
		message.Warnf("Unable to read package name. %s", err.Error())
		return err
	}

	namespaces, err := getNamespaces(commonZarfPath, rootZarfPath)
	if len(namespaces) == 0 {
		message.Warnf("No namespaces found. %s", err.Error())
		return err
	}

	message.Infof("Package Name: %s\n", packageName)
	message.Infof("Namespaces (%d): %v\n", len(namespaces), namespaces)

	// Check manifests in common/zarf.yaml (if exists) and in zarf.yaml.
	if commonZarfYamlExists {
		results = checkForManifests(commonZarfPath)
		allResults.Merge(results)
	}
	results = checkForManifests(rootZarfPath)
	allResults.Merge(results)

	// Check that flavors are defined in zarf.yaml.
	results = checkForFlavors(rootZarfPath)
	allResults.Merge(results)

	// Check that CODEOWNERS file contains a specific value.
	codeOwnersValue := []string{
		"/CODEOWNERS @jeff-mccoy @daveworth",
		"/LICENS* @jeff-mccoy @austenbryan",
	}
	results = checkCodeOwners(codeOwnersPath, codeOwnersValue)
	allResults.Merge(results)

	// Check for the existence of a tests directory.
	results = checkForTests(testsDir, testsYamlPath)
	allResults.Merge(results)

	// Check if sso is enabled
	results = checkKeycloakClient(udsValuesPath, udsPackagePath)
	allResults.Merge(results)

	if len(allResults.Warnings) > 0 {
		message.Infof("The following warnings were found:")
		logMessages(WarningSymbol, allResults.Warnings)
	}

	if len(allResults.Errors) > 0 {
		message.Infof("The following errors were found:")
		logMessages(ErrorSymbol, allResults.Errors)
		return fmt.Errorf("%d errors were found while performing badge verification", len(allResults.Errors))
	}

	return nil
}

// ==========================================================
// Badging Checks Functions
// ==========================================================

// checkForManifests checks if any manifests are present in the given Zarf YAML file,
// logs the result, and returns a CheckResults struct with errors, warnings, or successes.
func checkForManifests(zarfYamlFile string) CheckResults {
	var results CheckResults

	exists, err := atLeastOneExists(".components[] | select(.manifests != null)", zarfYamlFile)
	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to determine if manifests exist in %s", zarfYamlFile))
	} else {
		if exists {
			// Note: Append to Warnings, not Errors.
			results.Warnings = append(results.Warnings, fmt.Sprintf("Manifests present in %s", zarfYamlFile))
		} else {
			// Note: Append to Successes, not Errors.
			results.Successes = append(results.Successes, fmt.Sprintf("No manifests present in %s", zarfYamlFile))
		}
	}

	logResults(results)
	return results
}

// checkForFlavors verifies whether at least one flavor is defined in the given Zarf YAML file,
// logs the outcome, and returns a CheckResults struct indicating success or error.
func checkForFlavors(zarfYamlFile string) CheckResults {
	var results CheckResults

	exists, err := atLeastOneExists(".components[] | select(.only.flavor != null)", zarfYamlFile)

	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to determine if flavors are defined in %s", zarfYamlFile))
	} else {
		if exists {
			// Note: Append to Successes, not Errors.
			results.Successes = append(results.Successes, fmt.Sprintf("At least one flavor defined in %s", zarfYamlFile))
		} else {
			results.Errors = append(results.Errors, fmt.Sprintf("No flavors defined in %s", zarfYamlFile))
		}
	}

	logResults(results)
	return results
}

// checkCodeOwners verifies that the CODEOWNERS file contains the expected values,
// logs the outcome, and returns a CheckResults struct indicating success or error.
func checkCodeOwners(codeOwnersPath string, codeOwnersValues []string) CheckResults {
	var results CheckResults

	data, err := os.ReadFile(codeOwnersPath)
	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to read CODEOWNERS file %s", codeOwnersPath))
	} else {
		fileContent := string(data)
		lines := strings.Split(fileContent, "\n")

		// Loop over each expected value in the slice.
		for _, expected := range codeOwnersValues {
			found := false
			// Check each line in the file.
			for _, line := range lines {
				trimmedLine := strings.TrimSpace(line)
				if strings.Contains(trimmedLine, expected) {
					found = true
					break
				}
			}
			// Record results based on whether the expected value was found.
			if found {
				results.Successes = append(results.Successes, fmt.Sprintf("Found: %s", expected))
			} else {
				results.Errors = append(results.Errors, fmt.Sprintf("Not found in CODEOWERS: %s", expected))
			}
		}
	}
	logResults(results)
	return results
}

// check for the "tests" directory in the package to exist
func checkForTests(testsPath, yamlPath string) CheckResults {
	var results CheckResults

	// Check for the existence of a tests directory.
	if _, err := os.Stat(testsPath); os.IsNotExist(err) {
		results.Errors = append(results.Errors, fmt.Sprintf("No tests directory found at %s", testsPath))
	} else {
		results.Successes = append(results.Successes, fmt.Sprintf("Tests directory found at %s", testsPath))
	}

	// Check for the existence of a tasks/test.yaml.
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		results.Errors = append(results.Errors, fmt.Sprintf("YAML file not found at %s", yamlPath))
	} else {
		results.Successes = append(results.Successes, fmt.Sprintf("YAML file found at %s", yamlPath))
	}
	logResults(results)
	return results
}

func checkKeycloakClient(valuesPath, udsPackagePath string) CheckResults {
	var results CheckResults

	// Define SSOEntry struct to match each item in the sso list
	type SSOEntry struct {
		Name     string `yaml:"name"`
		ClientID string `yaml:"clientId"`
	}

	// Define Spec struct to hold the sso slice
	type Spec struct {
		SSO []SSOEntry `yaml:"sso"`
	}

	// Define Package struct to represent the entire YAML structure
	type Package struct {
		Spec Spec `yaml:"spec"`
	}

	// Check if sso key exists in values.yaml
	exists, err := atLeastOneExists(".sso | select(.enabled != null)", valuesPath)
	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to determine if SSO is enabled in %s", valuesPath))
	}

	enabled, err := utils.EvaluateYqToString(".sso.enabled", valuesPath)

	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to determine if SSO is enabled in %s", valuesPath))
	} else if exists && enabled == "true" {
		results.Successes = append(results.Successes, fmt.Sprintf("SSO is enabled in %s", valuesPath))
	} else {
		results.Successes = append(results.Successes, fmt.Sprintf("SSO is not enabled in %s", valuesPath))
	}

	// Read the YAML file
	file, err := os.ReadFile(udsPackagePath)
	fmt.Println(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
	}

	// Unmarshal the YAML content into the Package struct
	var pkg Package
	err = yaml.Unmarshal(file, &pkg)
	if err != nil {
		fmt.Println("Error parsing YAML:", err)
	}

	// Check if the sso section exists
	if len(pkg.Spec.SSO) == 0 {
		fmt.Println("No 'sso' entries found in 'spec'.")
	}

	// Iterate over the sso entries and print the name and clientId
	fmt.Println("SSO Entries:")
	for _, entry := range pkg.Spec.SSO {
		fmt.Printf("Name: %s, ClientID: %s\n", entry.Name, entry.ClientID)
	}

	logResults(results)
	return results
}

// ==========================================================
// Logging & Utility Functions
// ==========================================================

// logResults logs the Errors, Warnings, and Successes from a CheckResults struct using predefined symbols.
func logResults(results CheckResults) {
	logMessages(ErrorSymbol, results.Errors)
	logMessages(WarningSymbol, results.Warnings)
	logMessages(SuccessSymbol, results.Successes)
}

// logMessages prints each message in a slice prefixed by a specified symbol.
func logMessages(prefix rune, messages []string) {
	for _, m := range messages {
		message.Infof("%c %s", prefix, m)
	}
}

// atLeastOneExists evaluates a YAML query expression against a file and returns true if any result is found,
// or false along with an error if something goes wrong.
func atLeastOneExists(expression string, file string) (bool, error) {
	result, err := utils.EvaluateYqToString(expression, file)
	if err == nil {
		return len(result) > 0, nil
	}
	return false, nil
}

// getSliceOfValues runs a YAML query against a file, splits the resulting string by newline,
// and returns the values as a slice of strings.
func getSliceOfValues(expression string, file string) ([]string, error) {
	result, err := utils.EvaluateYqToString(expression, file)
	if err == nil {
		if len(result) > 0 {
			return strings.Split(result, "\n"), nil
		}
		return nil, nil
	}
	return nil, err
}

// fileExists checks whether a file exists at the specified path and ensures it is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// dedupe removes duplicate strings from the provided slice and returns a slice containing only unique values.
func dedupe(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, str := range input {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}
	return result
}

// getNamespaces extracts namespace values from the common and root Zarf YAML files,
func getNamespaces(commonZarfPath, rootZarfPath string) ([]string, error) {
	var namespaces []string

	processPath := func(path string) error {
		if fileExists(path) {
			values, err := getSliceOfValues(".components[].charts[].namespace  | select(. != null)", path)
			if err != nil {
				message.Infof("Error reading namespaces from %s - %s", path, err)
				return err
			}
			if len(values) > 0 {
				namespaces = append(namespaces, values...)
			}
		}
		return nil
	}

	if err := processPath(commonZarfPath); err != nil {
		message.Infof("Continuing despite error with %s", commonZarfPath)
	}
	err := processPath(rootZarfPath)
	namespaces = dedupe(namespaces)
	sort.Strings(namespaces)
	return namespaces, err
}
