// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"encoding/json"
	"fmt"
	"strings"

	profileschema "github.com/defenseunicorns/uds-pk/schemas"
	"github.com/xeipuuv/gojsonschema"
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

	var document any
	if err := yaml.Unmarshal(p.source, &document); err != nil {
		return fmt.Errorf("parsing profile for schema validation: %w", err)
	}
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("converting profile for schema validation: %w", err)
	}

	result, err := gojsonschema.Validate(
		gojsonschema.NewBytesLoader(schemaData),
		gojsonschema.NewBytesLoader(documentJSON),
	)
	if err != nil {
		return fmt.Errorf("validating profile schema: %w", err)
	}
	if result.Valid() {
		return nil
	}

	validationErrors := make([]string, 0, len(result.Errors()))
	for _, validationError := range result.Errors() {
		validationErrors = append(validationErrors, validationError.String())
	}
	return fmt.Errorf("profile does not match schema: %s", strings.Join(validationErrors, "; "))
}
