// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"fmt"
)

type FamilyHandler interface {
	Metadata(profile *Profile, bench *xccdfBenchmark) FamilyMetadata
	Evaluate(profile *Profile, groupID, ruleVersion, ruleTitle, checkContent, discussion string) (string, string, string)
}

type asdHandler struct{}

func (asdHandler) Metadata(_ *Profile, _ *xccdfBenchmark) FamilyMetadata {
	return FamilyMetadata{
		Revision:       STIGRevision,
		ChecklistSlug:  "asd",
		TargetRole:     "Application Server",
		TechnologyArea: "Application Review",
		STIGName:       "Application Security and Development Security Technical Implementation Guide",
		DisplayName:    "Application Security and Development",
		STIGID:         "Application_Security_Development_STIG",
	}
}

func (asdHandler) Evaluate(profile *Profile, groupID, ruleVersion, ruleTitle, checkContent, discussion string) (string, string, string) {
	return Evaluate(profile, groupID, ruleVersion, ruleTitle, checkContent, discussion)
}

type rhel9Handler struct{}

func (rhel9Handler) Metadata(profile *Profile, bench *xccdfBenchmark) FamilyMetadata {
	role := coalesce(profile.Platform.HostRole, "Operating System")
	var title, id string
	if bench != nil {
		title = bench.Title
		id = bench.ID
	}
	return FamilyMetadata{
		Revision:       STIGRevision,
		ChecklistSlug:  "rhel9",
		TargetRole:     role,
		TechnologyArea: "Operating System Review",
		STIGName:       coalesce(title, "Red Hat Enterprise Linux 9 Security Technical Implementation Guide"),
		DisplayName:    coalesce(title, "Red Hat Enterprise Linux 9"),
		STIGID:         coalesce(id, "RHEL_9_STIG"),
	}
}

func (rhel9Handler) Evaluate(profile *Profile, groupID, ruleVersion, ruleTitle, checkContent, discussion string) (string, string, string) {
	return EvaluateRHEL9(profile, groupID, ruleVersion, ruleTitle, checkContent, discussion)
}

func handlerForFamily(f Family) (FamilyHandler, error) {
	switch f {
	case "", FamilyASD:
		return asdHandler{}, nil
	case FamilyRHEL9:
		return rhel9Handler{}, nil
	default:
		return nil, fmt.Errorf("unsupported STIG family %q", f)
	}
}

func ResolveFamilyHandler(profile *Profile) (FamilyHandler, error) {
	return handlerForFamily(profile.EffectiveFamily())
}

func ChecklistTitle(profile *Profile, meta FamilyMetadata) string {
	return profile.AppName + "-" + meta.ChecklistSlug + "-" + meta.Revision
}

func DefaultChecklistFilename(profile *Profile, meta FamilyMetadata) string {
	return ChecklistTitle(profile, meta) + ".cklb"
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
