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

const namespaceExpression = ".components[0].charts[0].namespace"

func VerifyBadge(baseDir string) error {
	var errors []string

	commonZarfPath := filepath.Join(baseDir, "common", "zarf.yaml")
	rootZarfPath := filepath.Join(baseDir, "zarf.yaml")

	commonZarfYamlExists := fileExists(commonZarfPath)

	packageName, err := utils.EvaluateYqToString(".metadata.name", rootZarfPath)
	if err != nil {
		message.Warnf("Unable to read package name. %s", err.Error())
		return err
	}

	var namespace string
	if commonZarfYamlExists {
		namespace, err = utils.EvaluateYqToString(namespaceExpression, commonZarfPath)
	} else {
		namespace, err = utils.EvaluateYqToString(namespaceExpression, rootZarfPath)
	}
	if err != nil {
		message.Warnf("Unable to read namespace. %s", err.Error())
		return err
	}

	message.Infof("Package Name: %s\n", packageName)
	message.Infof("Namespace: %s\n", namespace)

	if commonZarfYamlExists {
		checkForManifests(commonZarfPath, &errors)
	}

	checkForManifests(rootZarfPath, &errors)

	if len(errors) > 0 {
		message.Infof("The following errors were found:")
		for _, e := range errors {
			message.Infof(e)
		}
	}

	return nil
}

func checkForManifests(zarfYamlFile string, errors *[]string) {
	exists, err := manifestsExist(zarfYamlFile)
	if err != nil {
		msg := fmt.Sprintf("❌ Unable to determine if manifests exist in %s", zarfYamlFile)
		message.Infof(msg)
		*errors = append(*errors, msg)
	} else {
		if exists {
			msg := fmt.Sprintf("❌ Manifests present in %s", zarfYamlFile)
			message.Infof(msg)
			*errors = append(*errors, msg)
		} else {
			message.Infof("✅ No manifests present in %s", zarfYamlFile)
		}
	}
}

func manifestsExist(file string) (bool, error) {
	manifests, err := utils.EvaluateYqToString(".components[] | select(.manifests != null)", file)
	if err == nil {
		return len(manifests) > 0, nil
	}
	return false, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
