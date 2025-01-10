// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package schema

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestYamlToJSON(t *testing.T) {
	// Create a temporary YAML file
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "values.yaml")
	yamlContent := `
key: value
number: 123
nested:
  child: "string value"
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test YAML file: %v", err)
	}

	got, err := yamlToJSON(yamlPath)
	if err != nil {
		t.Fatalf("yamlToJSON returned error: %v", err)
	}

	if got["key"] != "value" {
		t.Errorf("expected key to be 'value', got: %v", got["key"])
	}

	// Check numeric value in a more relaxed way using reflection
	numVal, ok := got["number"]
	if !ok {
		t.Errorf("expected 'number' to be present")
	} else {
		// Check if numVal is a numeric type
		valType := reflect.TypeOf(numVal).Kind()
		switch valType {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			// It's numeric, test passes
		default:
			t.Errorf("expected 'number' to be numeric, got: %T", numVal)
		}
	}

	nested, ok := got["nested"].(map[string]interface{})
	if !ok {
		t.Errorf("expected nested to be a map, got: %T", got["nested"])
	} else {
		if nested["child"] != "string value" {
			t.Errorf("expected nested.child to be 'string value', got: %v", nested["child"])
		}
	}
}

func TestGenerateBaseSchema(t *testing.T) {
	data := map[string]interface{}{
		"stringKey": "value",
		"numKey":    1.23,
		"boolKey":   true,
		"nullKey":   nil,
		"arrKey":    []interface{}{"one", "two"},
		"objKey": map[string]interface{}{
			"child": "childVal",
		},
	}

	schema := generateBaseSchema(data)

	if schema["type"] != "object" {
		t.Errorf("expected top-level type to be object, got: %v", schema["type"])
	}

	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected properties to be a map, got: %T", schema["properties"])
	}

	if props["stringKey"].(map[string]interface{})["type"] != "string" {
		t.Errorf("expected stringKey to have type string")
	}

	if props["numKey"].(map[string]interface{})["type"] != "number" {
		t.Errorf("expected numKey to have type number")
	}

	if props["boolKey"].(map[string]interface{})["type"] != "boolean" {
		t.Errorf("expected boolKey to have type boolean")
	}

	if props["nullKey"].(map[string]interface{})["type"] != "null" {
		t.Errorf("expected nullKey to have type null")
	}

	if props["arrKey"].(map[string]interface{})["type"] != "array" {
		t.Errorf("expected arrKey to have type array")
	}

	if props["objKey"].(map[string]interface{})["type"] != "object" {
		t.Errorf("expected objKey to have type object")
	}
}

func TestMapToSchema(t *testing.T) {
	data := map[string]interface{}{
		"simple": "value",
		"nested": map[string]interface{}{
			"inner": 123,
		},
		"list": []interface{}{
			map[string]interface{}{"itemKey": "itemVal"},
		},
	}

	props := mapToSchema(data)

	simpleSchema := props["simple"].(map[string]interface{})
	if simpleSchema["type"] != "string" {
		t.Errorf("expected simple to be string, got: %v", simpleSchema["type"])
	}

	nestedSchema := props["nested"].(map[string]interface{})
	if nestedSchema["type"] != "object" {
		t.Errorf("expected nested to be object, got: %v", nestedSchema["type"])
	}

	listSchema := props["list"].(map[string]interface{})
	if listSchema["type"] != "array" {
		t.Errorf("expected list to be array, got: %v", listSchema["type"])
	}

	items := listSchema["items"].(map[string]interface{})
	if items["type"] != "object" {
		t.Errorf("expected items to be object, got: %v", items["type"])
	}

	itemProps := items["properties"].(map[string]interface{})
	if itemProps["itemKey"].(map[string]interface{})["type"] != "string" {
		t.Errorf("expected itemKey to be string")
	}
}

func TestReplaceNestedSchemas(t *testing.T) {
	base := map[string]interface{}{
		"properties": map[string]interface{}{
			"key1": map[string]interface{}{
				"type": "string",
			},
			"nested": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"key2": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}

	custom := map[string]interface{}{
		"key1": map[string]interface{}{
			"type": "number",
		},
	}

	replaceNestedSchemas(base, custom)

	// After replacement, key1 should be replaced with custom schema
	if ((base["properties"].(map[string]interface{})["key1"]).(map[string]interface{})["type"]) != "number" {
		t.Errorf("expected key1 type to be number after replacement")
	}

	// key2 remains unchanged since it's not in custom
	nestedProps := (base["properties"].(map[string]interface{})["nested"]).(map[string]interface{})["properties"].(map[string]interface{})
	if nestedProps["key2"].(map[string]interface{})["type"] != "string" {
		t.Errorf("expected key2 to remain string")
	}
}
