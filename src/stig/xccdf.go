// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

// XCCDF XML types for parsing.

type xccdfBenchmark struct {
	XMLName   xml.Name     `xml:"Benchmark"`
	ID        string       `xml:"id,attr"`
	Title     string       `xml:"title"`
	PlainText []xccdfPlain `xml:"plain-text"`
	Groups    []xccdfGroup `xml:"Group"`
}

type xccdfPlain struct {
	ID   string `xml:"id,attr"`
	Text string `xml:",chardata"`
}

type xccdfGroup struct {
	ID          string    `xml:"id,attr"`
	Title       string    `xml:"title"`
	Description string    `xml:"description"`
	Rule        xccdfRule `xml:"Rule"`
}

type xccdfRule struct {
	ID       string       `xml:"id,attr"`
	Severity string       `xml:"severity,attr"`
	Weight   string       `xml:"weight,attr"`
	Title    string       `xml:"title"`
	Version  string       `xml:"version"`
	Desc     string       `xml:"description"`
	FixText  string       `xml:"fixtext"`
	Check    xccdfCheck   `xml:"check"`
	Idents   []xccdfIdent `xml:"ident"`
	Ref      *xccdfRef    `xml:"reference"`
}

type xccdfCheck struct {
	Content    string        `xml:"check-content"`
	ContentRef xccdfCheckRef `xml:"check-content-ref"`
}

type xccdfCheckRef struct {
	Href string `xml:"href,attr"`
	Name string `xml:"name,attr"`
}

type xccdfIdent struct {
	System string `xml:"system,attr"`
	Text   string `xml:",chardata"`
}

type xccdfRef struct {
	Identifier string `xml:"identifier"`
}

func ParseXCCDF(path string, profile *Profile) (*STIG, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var bench xccdfBenchmark
	if err := xml.Unmarshal(data, &bench); err != nil {
		return nil, fmt.Errorf("parsing XCCDF: %w", err)
	}

	definition, err := definitionForProfile(profile)
	if err != nil {
		return nil, err
	}

	releaseInfo := ""
	for _, pt := range bench.PlainText {
		if pt.ID == "release-info" {
			releaseInfo = pt.Text
			break
		}
	}

	stigUUID := uuid.New().String()
	var rules []Rule
	var refID *string

	for _, g := range bench.Groups {
		r := g.Rule

		// Extract CCIs and legacy IDs from idents
		var ccis, legacyIDs []string
		for _, ident := range r.Idents {
			if strings.HasPrefix(ident.Text, "CCI-") {
				ccis = append(ccis, ident.Text)
			} else if ident.Text != "" {
				legacyIDs = append(legacyIDs, ident.Text)
			}
		}

		// Reference identifier
		var ruleRefID *string
		if r.Ref != nil && r.Ref.Identifier != "" {
			s := r.Ref.Identifier
			ruleRefID = &s
			if refID == nil {
				refID = &s
			}
		}

		// Extract discussion from description
		discussion := extractXMLTag(r.Desc, "VulnDiscussion")
		if discussion == "" {
			discussion = r.Desc
		}

		// Extract metadata fields from description
		falsePos := extractXMLTag(r.Desc, "FalsePositives")
		falseNeg := extractXMLTag(r.Desc, "FalseNegatives")
		documentable := extractXMLTag(r.Desc, "Documentable")
		if documentable == "" {
			documentable = "false"
		}
		secOverride := extractXMLTag(r.Desc, "SeverityOverrideGuidance")
		potImpacts := extractXMLTag(r.Desc, "PotentialImpacts")
		thirdParty := extractXMLTag(r.Desc, "ThirdPartyTools")
		iaControls := extractXMLTag(r.Desc, "IAControls")
		responsibility := extractXMLTag(r.Desc, "Responsibility")
		mitigations := extractXMLTag(r.Desc, "Mitigations")
		mitControl := extractXMLTag(r.Desc, "MitigationControl")

		// Check content ref
		var checkRef *CheckContentRef
		if r.Check.ContentRef.Href != "" {
			checkRef = &CheckContentRef{
				Href: r.Check.ContentRef.Href,
				Name: r.Check.ContentRef.Name,
			}
		}

		// Evaluate the rule
		status, findingDetails, comments := evaluateRule(definition, profile, g.ID, r.Version, r.Title, r.Check.Content, discussion)

		// Apply per-rule overrides from profile
		if ov, ok := profile.Overrides[r.Version]; ok {
			if ov.Status != "" {
				status = ov.Status
			}
			if ov.FindingDetails != "" {
				findingDetails = ov.FindingDetails
			}
			if ov.Comments != "" {
				comments = ov.Comments
			}
		}

		// Pretty IDs
		ruleIDPretty := strings.ReplaceAll(r.ID, "xccdf_mil.disa.stig_rule_", "")
		ruleIDPretty = strings.TrimSuffix(ruleIDPretty, "_rule")
		groupIDPretty := strings.ReplaceAll(g.ID, "xccdf_mil.disa.stig_group_", "")

		if ccis == nil {
			ccis = []string{}
		}
		if legacyIDs == nil {
			legacyIDs = []string{}
		}

		rule := Rule{
			GroupIDSrc: g.ID,
			GroupTree: []GroupTreeEntry{{
				ID:          g.ID,
				Title:       g.Title,
				Description: "<GroupDescription></GroupDescription>",
			}},
			GroupID:           groupIDPretty,
			Severity:          r.Severity,
			GroupTitle:        r.Title,
			RuleIDSrc:         r.ID,
			RuleID:            ruleIDPretty,
			RuleVersion:       r.Version,
			RuleTitle:         r.Title,
			FixText:           r.FixText,
			Weight:            r.Weight,
			CheckContent:      r.Check.Content,
			CheckContentRef:   checkRef,
			Classification:    "Unclassified",
			Discussion:        discussion,
			FalsePositives:    falsePos,
			FalseNegatives:    falseNeg,
			Documentable:      documentable,
			SecurityOverride:  secOverride,
			PotentialImpacts:  potImpacts,
			ThirdPartyTools:   thirdParty,
			IAControls:        iaControls,
			Responsibility:    responsibility,
			Mitigations:       mitigations,
			MitigationControl: mitControl,
			LegacyIDs:         legacyIDs,
			CCIs:              ccis,
			ReferenceID:       ruleRefID,
			UUID:              uuid.New().String(),
			SIGUUID:           stigUUID,
			Status:            status,
			Overrides:         map[string]any{},
			Comments:          comments,
			FindingDetails:    findingDetails,
		}
		rules = append(rules, rule)
	}

	stigName, displayName, stigID := stigMetadata(definition, &bench)

	return &STIG{
		STIGName:            stigName,
		DisplayName:         displayName,
		STIGID:              stigID,
		ReleaseInfo:         releaseInfo,
		UUID:                stigUUID,
		ReferenceIdentifier: refID,
		Size:                len(rules),
		Rules:               rules,
	}, nil
}

func BuildChecklist(profile *Profile, stig *STIG) *Checklist {
	definition, err := definitionForProfile(profile)
	if err != nil {
		panic(err)
	}

	return &Checklist{
		Title:       ChecklistTitle(profile.AppName, definition),
		ID:          uuid.New().String(),
		CKLBVersion: "1.0",
		Active:      false,
		Mode:        1,
		HasPath:     true,
		TargetData: &TargetData{
			TargetType:     "Computing",
			HostName:       profile.AppName,
			IPAddress:      "",
			MACAddress:     "",
			FQDN:           profile.FQDN,
			Comments:       profile.Description,
			Role:           targetRole(definition, profile),
			IsWebDatabase:  false,
			TechnologyArea: definition.TechnologyArea,
			WebDBSite:      "",
			WebDBInstance:  "",
		},
		STIGs: []STIG{*stig},
	}
}

func definitionForProfile(profile *Profile) (STIGDefinition, error) {
	if profile == nil || profile.SelectedSTIG == nil {
		return STIGDefinition{}, fmt.Errorf("no supported STIG found in profile")
	}
	return LookupSTIGDefinition(profile.SelectedSTIG.ID)
}

func evaluateRule(definition STIGDefinition, profile *Profile, groupID, ruleVersion, ruleTitle, checkContent, discussion string) (string, string, string) {
	switch definition.ID {
	case RHEL9STIGProfileKey:
		return EvaluateRHEL9(profile, groupID, ruleVersion, ruleTitle, checkContent, discussion)
	default:
		return Evaluate(profile, groupID, ruleVersion, ruleTitle, checkContent, discussion)
	}
}

func stigMetadata(definition STIGDefinition, bench *xccdfBenchmark) (string, string, string) {
	switch definition.ID {
	case RHEL9STIGProfileKey:
		return coalesce(bench.Title, definition.STIGName), coalesce(bench.Title, definition.DisplayName), coalesce(bench.ID, definition.STIGID)
	default:
		return definition.STIGName, definition.DisplayName, definition.STIGID
	}
}

func targetRole(definition STIGDefinition, profile *Profile) string {
	switch definition.ID {
	case RHEL9STIGProfileKey:
		return coalesce(profile.Platform.HostRole, definition.TargetRole)
	default:
		return definition.TargetRole
	}
}

func extractXMLTag(text, tag string) string {
	start := strings.Index(text, "<"+tag+">")
	end := strings.Index(text, "</"+tag+">")
	if start >= 0 && end > start {
		return strings.TrimSpace(text[start+len("<"+tag+">") : end])
	}
	return ""
}
