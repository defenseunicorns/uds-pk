// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/zarf-dev/zarf/src/pkg/message"
	syaml "sigs.k8s.io/yaml"
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
	packageName, err := utils.EvaluateYqToString(".metadata.name", rootZarfPath)
	commonZarfYamlExists := utils.FileExists(commonZarfPath)
	codeOwnersPath := filepath.Join(baseDir, "CODEOWNERS")
	testsDir := filepath.Join(baseDir, "tests")
	testsYamlPath := filepath.Join(baseDir, "tasks/test.yaml")
	udsValuesPath := filepath.Join(baseDir, "chart/values.yaml")
	udsPackagePath := filepath.Join(baseDir, "chart/templates/uds-package.yaml")

	if err != nil {
		message.Warnf("Unable to read package name. %s", err.Error())
		return err
	}

	namespaces, err := utils.GetNamespaces(commonZarfPath, rootZarfPath)
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
	results = checkKeycloakClient(udsValuesPath, udsPackagePath, packageName)
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

	exists, err := utils.AtLeastOneExists(".components[] | select(.manifests != null)", zarfYamlFile)
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

	exists, err := utils.AtLeastOneExists(".components[] | select(.only.flavor != null)", zarfYamlFile)

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

		for _, expected := range codeOwnersValues {
			found := false

			for _, line := range lines {
				trimmedLine := strings.TrimSpace(line)
				if strings.Contains(trimmedLine, expected) {
					found = true
					break
				}
			}

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

// check to see if sso is enabled in values.yaml
// if enabled, verify the clientID and secret name are standardized
func checkKeycloakClient(valuesPath, udsPackagePath, packageName string) CheckResults {
	var results CheckResults

	// Check if sso key exists in values.yaml.
	exists, err := utils.AtLeastOneExists(".sso | select(.enabled != null)", valuesPath)
	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to determine if SSO is enabled in %s", valuesPath))
	}
	enabled, err := utils.EvaluateYqToString(".sso.enabled", valuesPath)
	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to determine if SSO is enabled in %s", valuesPath))
	} else if exists && enabled == "true" {
		results.Successes = append(results.Successes, fmt.Sprintf("SSO is enabled in %s", valuesPath))

		// if sso is enabled, check for the client id and secret name

		// Define data for template rendering.
		data := map[string]interface{}{
			"Values": map[string]interface{}{
				"sso": map[string]interface{}{
					"enabled": true,
				},
			},
		}

		// Render the uds-package from the udsPackagePath.
		renderedBytes, err := utils.RenderTemplate(udsPackagePath, data)
		if err != nil {
			results.Errors = append(results.Errors, fmt.Sprintf("Error rendering template from %s: %v", udsPackagePath, err))
			logResults(results)
			return results
		}

		// Define structs to unmarshal the YAML.
		type SSOEntry struct {
			Name     string `yaml:"name"`
			ClientID string `yaml:"clientId"`
		}
		type Spec struct {
			SSO []SSOEntry `yaml:"sso"`
		}
		type Package struct {
			Spec Spec `yaml:"spec"`
		}

		// Unmarshal the rendered YAML.
		var pkg Package
		if err := syaml.Unmarshal(renderedBytes, &pkg); err != nil {
			results.Errors = append(results.Errors, fmt.Sprintf("Error parsing YAML from %s: %v", udsPackagePath, err))
			logResults(results)
			return results
		}

		// Verify that there is at least one SSO entry.
		if len(pkg.Spec.SSO) == 0 {
			results.Errors = append(results.Errors, fmt.Sprintf("SSO is set as enabled, but no 'sso' entries found in %s", udsPackagePath))
			logResults(results)
			return results
		}

		// Validate each SSO entry's ClientID.
		// Accept if protocol is either "saml" or "oidc".
		validProtocols := []string{"saml", "oidc"}
		for _, entry := range pkg.Spec.SSO {
			match := false
			for _, prot := range validProtocols {
				expectedClientID := fmt.Sprintf("uds-package-%s-%s", packageName, prot)
				if entry.ClientID == expectedClientID {
					results.Successes = append(results.Successes, fmt.Sprintf("Matching ClientID found for protocol '%s': %s", prot, entry.ClientID))
					match = true
					break
				}
			}
			if !match {
				results.Errors = append(results.Errors, fmt.Sprintf("ClientID in uds-package-%s does not match expected format (uds-package-%s-[saml|oidc])", packageName, packageName))
			}
		}

	} else {
		results.Successes = append(results.Successes, fmt.Sprintf("SSO is not enabled in %s", valuesPath))
	}

	logResults(results)
	return results
}

// ==========================================================
// Logging
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
