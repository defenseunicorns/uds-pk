// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package schemas

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed stig-profile.schema.json
var stigProfileSchema []byte

func RenderSTIGProfile(version, schemaID string) ([]byte, error) {
	return Render(stigProfileSchema, version, schemaID)
}

func Render(source []byte, version, schemaID string) ([]byte, error) {
	var schema map[string]any
	if err := json.Unmarshal(source, &schema); err != nil {
		return nil, fmt.Errorf("parsing schema: %w", err)
	}

	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema is missing $defs")
	}
	metadata, ok := definitions["metadata"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema is missing $defs.metadata")
	}
	properties, ok := metadata["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema is missing $defs.metadata.properties")
	}
	versionProperty, ok := properties["version"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema is missing $defs.metadata.properties.version")
	}
	versionProperty["const"] = version
	if schemaID != "" {
		schema["$id"] = schemaID
	}

	rendered, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling schema: %w", err)
	}
	return append(rendered, '\n'), nil
}
