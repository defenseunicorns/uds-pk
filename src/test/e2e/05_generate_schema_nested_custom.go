// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemaGenerateNestedCustomCommand(t *testing.T) {
	// Create a sandbox directory for this test
	e2e.CreateSandboxDir(t)
	defer e2e.CleanupSandboxDir(t)

	// Source directory that contains the input files
	test := "05_generate_schema_nested_custom"
	sandboxDir := "src/test/sandbox"
	srcDir := filepath.Join("src/test/values_schemas", test)
	dir := filepath.Join(sandboxDir, test)
	// Copy the test files into the sandbox
	err := e2e.CopyDir(srcDir, filepath.Join(sandboxDir, test))
	require.NoError(t, err, "failed to copy test files into sandbox")
	// Run the command to generate the schema
	stdout, stderr, err := e2e.UDSPK("schema", "generate", "-b", dir)
	require.NoError(t, err, stdout, stderr)

	// Ensure the command output indicates success
	require.Contains(t, stderr, "All schemas match.")

	// Read the generated schema file
	schemaFile := filepath.Join("src", "test", "values_schemas", dir, "values.schema.json")
	data, err := os.ReadFile(schemaFile)
	require.NoError(t, err, "failed to read generated schema file")

	// Parse the generated schema
	var generatedSchema map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &generatedSchema), "failed to parse generated schema")

	// Verify that top-level additionalNetworkAllow is present and matches expected structure
	props, ok := generatedSchema["properties"].(map[string]interface{})
	require.True(t, ok, "expected top-level 'properties' to be a map")

	verifyAdditionalNetworkAllowStructure(t, props, "additionalNetworkAllow")

	// Verify nested additionalNetworkAllow under kubernetesSandbox
	kubernetesSandboxProps := getNestedProperties(t, props, "kubernetesSandbox")
	verifyAdditionalNetworkAllowStructure(t, kubernetesSandboxProps, "additionalNetworkAllow")
}

// verifyAdditionalNetworkAllowStructure checks that the given key in the provided properties map
// matches the structure defined in the additionalNetworkAllow schema, such as being an array with
// certain fields like "oneOf", "direction", etc.
func verifyAdditionalNetworkAllowStructure(t *testing.T, props map[string]interface{}, key string) {
	ana, ok := props[key].(map[string]interface{})
	require.True(t, ok, "expected '%s' to be a map", key)
	require.Equal(t, "array", ana["type"], "expected '%s' to have type 'array'", key)

	items, ok := ana["items"].(map[string]interface{})
	require.True(t, ok, "expected '%s' to have 'items'", key)
	require.Equal(t, "object", items["type"], "expected '%s.items' to be an object", key)

	// Check that oneOf is present
	oneOf, ok := items["oneOf"].([]interface{})
	require.True(t, ok, "expected '%s.items' to have 'oneOf' array", key)
	require.NotEmpty(t, oneOf, "expected '%s.items.oneOf' to not be empty", key)

	// Optionally check some known properties from additionalNetworkAllow.json (like 'direction', 'selector')
	itemProps, ok := items["properties"].(map[string]interface{})
	require.True(t, ok, "expected '%s.items' to have 'properties'", key)
	require.Contains(t, itemProps, "direction", "expected '%s.items.properties' to contain 'direction'", key)
	require.Contains(t, itemProps, "selector", "expected '%s.items.properties' to contain 'selector'", key)
}

// getNestedProperties is a helper function to navigate into nested schema objects.
// It assumes that the passed map is a 'properties' map, and that 'key' is an object with a 'properties' field.
func getNestedProperties(t *testing.T, parent map[string]interface{}, key string) map[string]interface{} {
	childRaw, ok := parent[key]
	require.True(t, ok, "expected '%s' key in parent properties", key)

	child, ok := childRaw.(map[string]interface{})
	require.True(t, ok, "expected '%s' to be a map", key)

	props, ok := child["properties"].(map[string]interface{})
	require.True(t, ok, "expected '%s' to have 'properties' map", key)

	return props
}
