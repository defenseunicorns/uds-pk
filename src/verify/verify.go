// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package verify

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

func VerifyBadge(baseDir string) error {
	fmt.Printf("Verify command called. packageDir=[%s]\n", baseDir)

	namespace, err := readNamespace(baseDir)

	if err != nil {
		return err
	}

	fmt.Printf("Found namespace %s\n", namespace)

	return nil
}

func readNamespace(baseDir string) (string, error) {
	commonZarfPath := filepath.Join(baseDir, "common", "zarf.yaml")
	rootZarfPath := filepath.Join(baseDir, "zarf.yaml")

	var path string

	if fileExists(commonZarfPath) {
		path = commonZarfPath
	} else {
		path = rootZarfPath
	}

	return getNamespaceFromZarfYaml(path)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func getNamespaceFromZarfYaml(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read file %s: %v", filePath, err)
	}

	pathQuery, err := yaml.PathString("$.components[*].charts[*].namespace")
	if err != nil {
		log.Fatalf("Invalid path query: %v", err)
		return "", err
	}

	// Use the path query to extract namespaces, wrapping data in bytes.NewReader
	var rawNamespaces []interface{}
	err = pathQuery.Read(bytes.NewReader(data), &rawNamespaces)
	if err != nil {
		log.Fatalf("Failed to extract namespaces from YAML file %s: %v", filePath, err)
		return "", err
	}

	// Find and return the first namespace
	for _, raw := range rawNamespaces {
		switch v := raw.(type) {
		case string:
			// Return the first string namespace
			return v, nil
		case []interface{}:
			// If it's a nested slice, look for the first string within it
			for _, nested := range v {
				if ns, ok := nested.(string); ok {
					return ns, nil
				}
			}
		default:
			log.Printf("Skipping non-string namespace: %v", raw)
		}
	}

	// Return an empty string if no valid namespace is found
	log.Println("No valid namespace found")
	return "", errors.New("no valid namespace found")
}
