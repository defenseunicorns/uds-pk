// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package verify

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/zarf-dev/zarf/src/pkg/message"
)

const NamespaceExpression = ".components[0].charts[0].namespace"
const WarningSymbol = '⚠'
const ErrorSymbol = '❌'
const SuccessSymbol = '✅'

type CheckResults struct {
	Errors    []string
	Warnings  []string
	Successes []string
}

func (r *CheckResults) Merge(other CheckResults) {
	r.Errors = append(r.Errors, other.Errors...)
	r.Warnings = append(r.Warnings, other.Warnings...)
	r.Successes = append(r.Successes, other.Successes...)
}

func VerifyBadge(baseDir string, failOnError bool) error {
	var allResults CheckResults
	var results CheckResults

	commonZarfPath := filepath.Join(baseDir, "common/zarf.yaml")
	rootZarfPath := filepath.Join(baseDir, "zarf.yaml")

	commonZarfYamlExists := fileExists(commonZarfPath)

	packageName, err := utils.EvaluateYqToString(".metadata.name", rootZarfPath)
	if err != nil {
		message.Warnf("Unable to read package name. %s", err.Error())
		return err
	}

	var namespace string
	if commonZarfYamlExists {
		namespace, err = utils.EvaluateYqToString(NamespaceExpression, commonZarfPath)
	} else {
		namespace, err = utils.EvaluateYqToString(NamespaceExpression, rootZarfPath)
	}
	if err != nil {
		message.Warnf("Unable to read namespace. %s", err.Error())
		return err
	}

	message.Infof("Package Name: %s\n", packageName)
	message.Infof("Namespace: %s\n", namespace)

	// manifests should not be found in common/zarf.yaml or zarf.yaml
	if commonZarfYamlExists {
		results = checkForManifests(commonZarfPath)
		allResults.Merge(results)
	}
	results = checkForManifests(rootZarfPath)
	allResults.Merge(results)

	// flavors should be defined in zarf.yaml
	results = checkForFlavors(rootZarfPath)
	allResults.Merge(results)

	if len(allResults.Warnings) > 0 {
		message.Infof("The following warnings were found:")
		logMessages(WarningSymbol, allResults.Warnings)
	}

	if len(allResults.Errors) > 0 {
		message.Infof("The following errors were found:")
		logMessages(ErrorSymbol, allResults.Errors)
		if failOnError {
			return fmt.Errorf("%d errors were found while performing badge verification", len(allResults.Errors))
		}
	}

	return nil
}

func checkForManifests(zarfYamlFile string) CheckResults {
	var results CheckResults

	exists, err := atLeastOneExists(".components[] | select(.manifests != null)", zarfYamlFile)
	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to determine if manifests exist in %s", zarfYamlFile))
	} else {
		if exists {
			results.Errors = append(results.Errors, fmt.Sprintf("Manifests present in %s", zarfYamlFile))
		} else {
			results.Successes = append(results.Errors, fmt.Sprintf("No manifests present in %s", zarfYamlFile))
		}
	}

	logResults(results)
	return results
}

func checkForFlavors(zarfYamlFile string) CheckResults {
	var results CheckResults

	exists, err := atLeastOneExists(".components[] | select(.only.flavor != null)", zarfYamlFile)
	if err != nil {
		results.Errors = append(results.Errors, fmt.Sprintf("Unable to determine if flavors are defined in %s", zarfYamlFile))
	} else {
		if exists {
			results.Successes = append(results.Errors, fmt.Sprintf("At least one flavor defined in %s", zarfYamlFile))
		} else {
			results.Errors = append(results.Errors, fmt.Sprintf("No flavors defined in in %s", zarfYamlFile))
		}
	}

	logResults(results)
	return results
}

func atLeastOneExists(expression string, file string) (bool, error) {
	result, err := utils.EvaluateYqToString(expression, file)
	if err == nil {
		return len(result) > 0, nil
	}
	return false, nil
}

func logResults(results CheckResults) {
	logMessages(ErrorSymbol, results.Errors)
	logMessages(WarningSymbol, results.Warnings)
	logMessages(SuccessSymbol, results.Successes)
}

func logMessages(prefix rune, messages []string) {
	for _, m := range messages {
		message.Infof("%c %s", prefix, m)
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
