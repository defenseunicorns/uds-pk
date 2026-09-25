// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

func TestProfileSchema(t *testing.T) {
	schemaPath, err := filepath.Abs(filepath.Join("..", "..", "schemas", "stig-profile.schema.json"))
	require.NoError(t, err)
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)

	t.Run("accepts single STIG profile", func(t *testing.T) {
		document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
		result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewGoLoader(document))
		require.NoError(t, err)
		require.True(t, result.Valid(), result.Errors())
	})

	t.Run("accepts multiple STIG profile", func(t *testing.T) {
		document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-multi-profile.yaml"))
		result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewGoLoader(document))
		require.NoError(t, err)
		require.True(t, result.Valid(), result.Errors())
	})

	t.Run("rejects a different schema version", func(t *testing.T) {
		document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
		metadata := document["metadata"].(map[string]any)
		metadata["version"] = "1.2.3"

		result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewGoLoader(document))
		require.NoError(t, err)
		require.False(t, result.Valid())
	})

	for _, status := range []string{"not_a_finding", "not_applicable", "not_reviewed", "open"} {
		t.Run("accepts override status "+status, func(t *testing.T) {
			document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
			stigs := document["stigs"].([]any)
			stigProfile := stigs[0].(map[string]any)
			stigProfile["overrides"] = map[string]any{
				"APSC-DV-000160": map[string]any{"status": status},
			}

			result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewGoLoader(document))
			require.NoError(t, err)
			require.True(t, result.Valid(), result.Errors())
		})
	}

	t.Run("rejects an unsupported override status", func(t *testing.T) {
		document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
		stigs := document["stigs"].([]any)
		stigProfile := stigs[0].(map[string]any)
		stigProfile["overrides"] = map[string]any{
			"APSC-DV-000160": map[string]any{"status": "passed"},
		}

		result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewGoLoader(document))
		require.NoError(t, err)
		require.False(t, result.Valid())
	})

	for name, appName := range map[string]string{
		"forward slash":  "../other/file",
		"backward slash": `..\other\file`,
	} {
		t.Run("rejects name with "+name, func(t *testing.T) {
			document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
			metadata := document["metadata"].(map[string]any)
			metadata["name"] = appName

			result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewGoLoader(document))
			require.NoError(t, err)
			require.False(t, result.Valid())
		})
	}
}

func loadYAMLDocument(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, yaml.Unmarshal(data, &document))

	jsonData, err := json.Marshal(document)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(jsonData, &document))
	return document
}
