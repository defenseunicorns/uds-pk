// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestProfileSchema(t *testing.T) {
	schemaPath, err := filepath.Abs(filepath.Join("..", "..", "schemas", "stig-profile.schema.json"))
	require.NoError(t, err)
	schema, err := jsonschema.NewCompiler().Compile(schemaPath)
	require.NoError(t, err)

	t.Run("accepts single STIG profile", func(t *testing.T) {
		document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
		err := schema.Validate(document)
		require.NoError(t, err)
	})

	t.Run("accepts multiple STIG profile", func(t *testing.T) {
		document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-multi-profile.yaml"))
		err := schema.Validate(document)
		require.NoError(t, err)
	})

	t.Run("rejects a different schema version", func(t *testing.T) {
		document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
		metadata := document["metadata"].(map[string]any)
		metadata["version"] = "1.2.3"

		err := schema.Validate(document)
		require.Error(t, err)
	})

	for _, status := range []string{"not_a_finding", "not_applicable", "not_reviewed", "open"} {
		t.Run("accepts override status "+status, func(t *testing.T) {
			document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
			stigs := document["stigs"].([]any)
			stigProfile := stigs[0].(map[string]any)
			stigProfile["overrides"] = map[string]any{
				"APSC-DV-000160": map[string]any{"status": status},
			}

			err := schema.Validate(document)
			require.NoError(t, err)
		})
	}

	t.Run("rejects an unsupported override status", func(t *testing.T) {
		document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
		stigs := document["stigs"].([]any)
		stigProfile := stigs[0].(map[string]any)
		stigProfile["overrides"] = map[string]any{
			"APSC-DV-000160": map[string]any{"status": "passed"},
		}

		err := schema.Validate(document)
		require.Error(t, err)
	})

	for name, appName := range map[string]string{
		"forward slash":  "../other/file",
		"backward slash": `..\other\file`,
	} {
		t.Run("rejects name with "+name, func(t *testing.T) {
			document := loadYAMLDocument(t, filepath.Join("..", "test", "stig", "test-profile.yaml"))
			metadata := document["metadata"].(map[string]any)
			metadata["name"] = appName

			err := schema.Validate(document)
			require.Error(t, err)
		})
	}
}

func TestProfileValidateSchema(t *testing.T) {
	for _, test := range []struct {
		name    string
		source  string
		wantErr string
	}{
		{
			name:   "accepts release version",
			source: "stigs:\n  - id: asd_v6r4\n",
		},
		{
			name:    "rejects missing required field",
			wantErr: "missing property 'stigs'",
		},
		{
			name:    "rejects empty STIG list",
			source:  "stigs: []\n",
			wantErr: "/stigs",
		},
		{
			name:    "rejects nested type mismatch",
			source:  "stigs:\n  - id: asd_v6r4\n    characteristics:\n      uses_soap: 'false'\n",
			wantErr: "/stigs/0/characteristics/uses_soap",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := &Profile{source: []byte("kind: UDS STIG Profile\nmetadata:\n  name: test-app\n  version: 1.2.3\n" + test.source)}
			err := profile.ValidateSchema("1.2.3")
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "profile does not match schema")
			require.ErrorContains(t, err, test.wantErr)
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
