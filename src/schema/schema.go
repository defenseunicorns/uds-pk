// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package schema

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/yudai/gojsondiff"
	"github.com/yudai/gojsondiff/formatter"
	"github.com/zarf-dev/zarf/src/pkg/message"
)

//go:embed schemas/*
var schemasFS embed.FS

func GenerateSchemas(baseDir string) error {
	valuesFiles, err := findFiles(baseDir, "values.yaml")
	if err != nil {
		return err
	}

	for _, valuesFile := range valuesFiles {
		outputFile := filepath.Join(filepath.Dir(valuesFile), "values.schema.json")
		message.Infof("Generating schema for %s...\n", valuesFile)

		baseSchema, err := buildSchemaForValuesFile(valuesFile)
		if err != nil {
			return err
		}

		// Write schema to file
		outputData, err := json.MarshalIndent(baseSchema, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(outputFile, outputData, 0644); err != nil {
			return err
		}
		message.Successf("Schema generated at %s\n", outputFile)
	}

	return nil
}

func ValidateSchemas(baseDir string) error {
	valuesFiles, err := findFiles(baseDir, "values.yaml")
	if err != nil {
		return err
	}

	differencesFound := false

	for _, valuesFile := range valuesFiles {
		outputFile := filepath.Join(filepath.Dir(valuesFile), "values.schema.json")
		message.Infof("Checking schema for %s...\n", valuesFile)

		baseSchema, err := buildSchemaForValuesFile(valuesFile)
		if err != nil {
			return err
		}

		// Read existing schema
		if _, err := os.Stat(outputFile); errors.Is(err, os.ErrNotExist) {
			message.Warnf("Existing schema not found at %s\n", outputFile)
			differencesFound = true
			continue
		}
		existingSchema, err := os.ReadFile(outputFile)
		if err != nil {
			return err
		}

		// Compare schemas
		generatedSchema, err := json.MarshalIndent(baseSchema, "", "  ")
		if err != nil {
			return err
		}
		if !strings.EqualFold(string(existingSchema), string(generatedSchema)) {
			message.Warnf("Schemas do not match for %s.\nDifferences:\n", valuesFile)
			fmt.Println(diffSchemas(string(existingSchema), string(generatedSchema)))
			differencesFound = true
		}
	}

	if differencesFound {
		message.Warn("Schema differences found.")
		return nil
	}

	message.Success("All schemas match.")
	return nil
}

func buildSchemaForValuesFile(valuesFile string) (map[string]interface{}, error) {
	// Convert YAML to JSON
	jsonData, err := yamlToJSON(valuesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML to JSON for %s: %w", valuesFile, err)
	}

	// Generate schema
	baseSchema := generateBaseSchema(jsonData) //TODO(ewyles) -- removed error return from this because it was always nil

	// Add custom schema
	customSchemas, err := LoadCustomSchemas()
	if err != nil {
		return nil, err
	}
	replaceNestedSchemas(baseSchema, customSchemas)

	return baseSchema, nil
}

func replaceNestedSchemas(base map[string]interface{}, custom map[string]interface{}) {
	if props, ok := base["properties"].(map[string]interface{}); ok {
		for k, v := range props {
			if customVal, exists := custom[k]; exists {
				props[k] = customVal
			} else if nestedMap, isMap := v.(map[string]interface{}); isMap {
				replaceNestedSchemas(nestedMap, custom)
			}
		}
	}
}

func diffSchemas(existing, generated string) string {
	var existingMap map[string]interface{}
	if err := json.Unmarshal([]byte(existing), &existingMap); err != nil {
		return fmt.Sprintf("Error parsing existing schema: %v", err)
	}

	var generatedMap map[string]interface{}
	if err := json.Unmarshal([]byte(generated), &generatedMap); err != nil {
		return fmt.Sprintf("Error parsing generated schema: %v", err)
	}

	differ := gojsondiff.New()
	diff := differ.CompareObjects(existingMap, generatedMap)

	if !diff.Modified() {
		return "No differences found."
	}

	asciiFormatter := formatter.NewAsciiFormatter(existingMap, formatter.AsciiFormatterConfig{})
	difference, err := asciiFormatter.Format(diff)
	if err != nil {
		return fmt.Sprintf("Error formatting differences: %v", err)
	}

	return difference
}

func findFiles(baseDir, pattern string) ([]string, error) {
	var files []string
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Base(path) == pattern {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func yamlToJSON(filePath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(data, &yamlData); err != nil {
		return nil, err
	}

	return yamlData, nil
}

// TODO(ewyles) -- refactored this a bit for reuse and made it a little easier to read (I think?)
func generateBaseSchema(data map[string]interface{}) map[string]interface{} {
	return objectSchema(mapToSchema(data))
}

func mapToSchema(data map[string]interface{}) map[string]interface{} {
	properties := make(map[string]interface{})
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			properties[key] = objectSchema(mapToSchema(v))
		case []interface{}:
			properties[key] = arraySchema(v)
		case string:
			properties[key] = typeSchema("string")
		case float64, int, uint64, int64:
			properties[key] = typeSchema("number")
		case bool:
			properties[key] = typeSchema("boolean")
		case nil:
			properties[key] = typeSchema("null")
		default:
			properties[key] = typeSchema(fmt.Sprintf("%T", value))
		}
	}
	return properties
}

func objectSchema(properties map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
}

func arraySchema(arr []interface{}) map[string]interface{} {
	items := map[string]interface{}{}
	if len(arr) > 0 {
		items = mapToSchema(map[string]interface{}{"item": arr[0]})["item"].(map[string]interface{})
	}

	return map[string]interface{}{
		"type":  "array",
		"items": items,
	}
}

func typeSchema(typeName string) map[string]interface{} {
	return map[string]interface{}{
		"type": typeName,
	}
}

func LoadCustomSchemas() (map[string]interface{}, error) {
	schemas := make(map[string]interface{})

	entries, err := schemasFS.ReadDir("schemas")
	if err != nil {
		return nil, fmt.Errorf("failed to read schemas directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fileName := entry.Name()
		if filepath.Ext(fileName) == ".json" {
			data, err := schemasFS.ReadFile("schemas/" + fileName)
			if err != nil {
				return nil, fmt.Errorf("failed to read schema file %s: %w", fileName, err)
			}

			var schema interface{}
			if err := json.Unmarshal(data, &schema); err != nil {
				return nil, fmt.Errorf("failed to parse schema file %s: %w", fileName, err)
			}

			baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
			schemas[baseName] = schema
		}
	}

	return schemas, nil
}
