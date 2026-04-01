// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	ProfileKind           = "UDS STIG Profile"
	ASDSTIGProfileKey     = "asd_v6r4"
	RHEL9STIGProfileKey   = "rhel9_v2r7"
)

func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	p.AppName = p.Metadata.Name
	p.FQDN = p.Metadata.FQDN
	p.Description = p.Metadata.Description
	if p.Kind != "" && p.Kind != ProfileKind {
		return nil, fmt.Errorf("kind must be %q in %s", ProfileKind, path)
	}
	if selected := p.selectDefaultSTIG(); selected != nil {
		p.SelectedSTIG = selected
		p.Chars = selected.Characteristics
		p.Platform = selected.Platform
		p.Overrides = selected.Overrides
	}
	if p.AppName == "" {
		return nil, fmt.Errorf("metadata.name is required in %s", path)
	}
	return &p, nil
}

func (p *Profile) SelectSTIG(id string) *STIGProfile {
	for i := range p.STIGs {
		if p.STIGs[i].ID == id {
			return &p.STIGs[i]
		}
	}
	return nil
}

func (p *Profile) selectDefaultSTIG() *STIGProfile {
	for i := range p.STIGs {
		if _, err := LookupSTIGDefinition(p.STIGs[i].ID); err == nil {
			return &p.STIGs[i]
		}
	}
	return nil
}
