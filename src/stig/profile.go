// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ProfileKind         = "UDS STIG Profile"
	ASDSTIGProfileKey   = "asd_v6r4"
	RHEL9STIGProfileKey = "rhel9_v2r7"
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
		p.ActivateSTIG(selected)
	}
	if p.AppName == "" {
		return nil, fmt.Errorf("metadata.name is required in %s", path)
	}
	if strings.ContainsAny(p.AppName, `/\`) {
		return nil, fmt.Errorf("metadata.name must not contain path separators in %s", path)
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

func (p *Profile) ValidateVersion(expected string) error {
	if p.Metadata.Version == "" {
		return fmt.Errorf("metadata.version is required")
	}
	if p.Metadata.Version != expected {
		return fmt.Errorf("metadata.version %q does not match uds-pk version %q", p.Metadata.Version, expected)
	}
	return nil
}

func (p *Profile) SupportedSTIGs() []*STIGProfile {
	stigs := make([]*STIGProfile, 0, len(p.STIGs))
	for i := range p.STIGs {
		if _, err := LookupSTIGDefinition(p.STIGs[i].ID); err == nil {
			stigs = append(stigs, &p.STIGs[i])
		}
	}
	return stigs
}

func (p *Profile) ActivateSTIG(selected *STIGProfile) {
	p.SelectedSTIG = selected
	p.Chars = selected.Characteristics
	p.Platform = selected.Platform
	p.Overrides = selected.Overrides
}

func (p *Profile) selectDefaultSTIG() *STIGProfile {
	stigs := p.SupportedSTIGs()
	if len(stigs) == 0 {
		return nil
	}
	return stigs[0]
}
