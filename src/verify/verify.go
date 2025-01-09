// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package verify

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

const namespacePath = "$.components[0].charts[0].namespace"

func VerifyBadge(baseDir string) error {
	fmt.Printf("Verify command called. packageDir=[%s]\n", baseDir)

	commonZarfPath := filepath.Join(baseDir, "common", "zarf.yaml")
	rootZarfPath := filepath.Join(baseDir, "zarf.yaml")

	packageName, err := getSingleYamlValue(rootZarfPath, "$.metadata.name")

	fmt.Printf("  ℹ️  Package Name: %s\n", packageName)

	if err != nil {
		return err
	}

	namespace, err := readNamespace(commonZarfPath, rootZarfPath)

	if err != nil {
		return err
	}

	fmt.Printf("  ℹ️  Namespace: %s\n", namespace)
	return nil
}

func readNamespace(commonZarfPath string, rootZarfPath string) (string, error) {
	namespacePath := "$.components[0].charts[0].namespace"

	if fileExists(commonZarfPath) {
		return getSingleYamlValue(commonZarfPath, namespacePath)
	} else {
		return getSingleYamlValue(rootZarfPath, namespacePath)
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func getSingleYamlValue(filePath string, yamlPath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read file %s: %v", filePath, err)
	}

	pathQuery, err := yaml.PathString(yamlPath)
	if err != nil {
		log.Fatalf("Invalid path query: %v", err)
		return "", err
	}

	var value string
	err = pathQuery.Read(bytes.NewReader(data), &value)
	if err != nil {
		log.Fatalf("Failed to extract value from YAML file: %v", err)
		return "", err
	}

	return value, nil
}
