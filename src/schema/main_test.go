// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderSchemaSetsProfileVersion(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "stig-profile.schema.json")
	sourcePath := filepath.Join("..", "..", "schemas", "stig-profile.schema.json")

	require.NoError(t, renderSchema(sourcePath, outputPath, "1.2.3"))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var schema map[string]any
	require.NoError(t, json.Unmarshal(data, &schema))
	require.Equal(t, "https://github.com/defenseunicorns/uds-pk/releases/download/v1.2.3/stig-profile-1.2.3.schema.json", schema["$id"])
	definitions := schema["$defs"].(map[string]any)
	metadata := definitions["metadata"].(map[string]any)
	properties := metadata["properties"].(map[string]any)
	version := properties["version"].(map[string]any)
	require.Equal(t, "1.2.3", version["const"])
}
