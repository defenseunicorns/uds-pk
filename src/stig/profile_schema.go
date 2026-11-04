// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"bytes"
	"encoding/json"
	"fmt"

	profileschema "github.com/defenseunicorns/uds-pk/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func (p *Profile) ValidateSchema(version string) error {
	if len(p.source) == 0 {
		return fmt.Errorf("profile source is unavailable")
	}

	schemaData, err := profileschema.RenderSTIGProfile(version, "")
	if err != nil {
		return fmt.Errorf("rendering profile schema: %w", err)
	}
	schemaDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaData))
	if err != nil {
		return fmt.Errorf("parsing profile schema: %w", err)
	}
	const schemaURL = "stig-profile.schema.json"
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		return fmt.Errorf("loading profile schema: %w", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		return fmt.Errorf("compiling profile schema: %w", err)
	}

	var document any
	if err := yaml.Unmarshal(p.source, &document); err != nil {
		return fmt.Errorf("parsing profile for schema validation: %w", err)
	}
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("converting profile for schema validation: %w", err)
	}

	document, err = jsonschema.UnmarshalJSON(bytes.NewReader(documentJSON))
	if err != nil {
		return fmt.Errorf("parsing profile JSON for schema validation: %w", err)
	}

	if err := schema.Validate(document); err != nil {
		return fmt.Errorf("profile does not match schema: %w", err)
	}
	return nil
}
