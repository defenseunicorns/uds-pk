// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	sourcePath := flag.String("source", "schemas/stig-profile.schema.json", "Path to the development STIG profile schema")
	outputPath := flag.String("output", "", "Path for the versioned STIG profile schema")
	version := flag.String("version", "", "uds-pk version for the STIG profile schema")
	flag.Parse()

	if *outputPath == "" || *version == "" {
		fmt.Fprintln(os.Stderr, "--output and --version are required")
		os.Exit(2)
	}
	if err := renderSchema(*sourcePath, *outputPath, *version); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func renderSchema(sourcePath, outputPath, version string) error {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("reading schema: %w", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		return fmt.Errorf("parsing schema: %w", err)
	}

	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		return fmt.Errorf("schema is missing $defs")
	}
	metadata, ok := definitions["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("schema is missing $defs.metadata")
	}
	properties, ok := metadata["properties"].(map[string]any)
	if !ok {
		return fmt.Errorf("schema is missing $defs.metadata.properties")
	}
	versionProperty, ok := properties["version"].(map[string]any)
	if !ok {
		return fmt.Errorf("schema is missing $defs.metadata.properties.version")
	}
	versionProperty["const"] = version
	schema["$id"] = fmt.Sprintf("https://github.com/defenseunicorns/uds-pk/releases/download/v%s/stig-profile-%s.schema.json", version, version)

	rendered, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling schema: %w", err)
	}
	rendered = append(rendered, '\n')

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	if err := os.WriteFile(outputPath, rendered, 0o644); err != nil {
		return fmt.Errorf("writing schema: %w", err)
	}
	return nil
}
