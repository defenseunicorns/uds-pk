// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
)

const sourceDataStreamNamespace = "http://scap.nist.gov/schema/scap/source/1.2"
const xlinkNamespace = "http://www.w3.org/1999/xlink"
const ssgRulePrefix = "xccdf_org.ssgproject.content_rule_"

type ScanEvidence struct {
	bySTIGID        map[string][]XCCDFRuleResult
	expectedRuleIDs map[string]map[string]struct{}
	ruleReferences  map[string][]string
}

type ssgRule struct {
	ID         string         `xml:"id,attr"`
	References []ssgReference `xml:"reference"`
}

type ssgReference struct {
	XMLName xml.Name
	Href    string `xml:"href,attr"`
	Value   string `xml:",chardata"`
}

type ssgBenchmark struct {
	version         string
	profileFound    bool
	profileSettings []string
	mappings        map[string][]string
}

type ssgComponentBenchmark struct {
	componentID string
	benchmark   ssgBenchmark
}

// LoadScanEvidence joins OpenSCAP results to DISA rule IDs through SSG references.
func LoadScanEvidence(resultsPath, dataStreamPath string) (*ScanEvidence, error) {
	results, err := LoadXCCDFResults(resultsPath)
	if err != nil {
		return nil, err
	}
	if results.ProfileID == "" {
		return nil, fmt.Errorf("results must identify the selected scan profile")
	}
	stream, err := loadSSGReferences(dataStreamPath, results.BenchmarkID, results.ProfileID)
	if err != nil {
		return nil, err
	}
	if results.BenchmarkVersion == "" || stream.version == "" {
		return nil, fmt.Errorf("results and data stream must both contain a benchmark version")
	}
	if results.BenchmarkVersion != stream.version {
		return nil, fmt.Errorf("results benchmark version %q does not match data stream version %q", results.BenchmarkVersion, stream.version)
	}
	resultBenchmark, err := loadResultSSGReferences(resultsPath, results.BenchmarkID, results.ProfileID)
	if err != nil {
		return nil, err
	}
	if !resultBenchmark.profileFound || !slices.Equal(resultBenchmark.profileSettings, stream.profileSettings) {
		return nil, fmt.Errorf("results profile %q does not match the data stream profile", results.ProfileID)
	}
	for ruleID, resultRefs := range resultBenchmark.mappings {
		if !sameReferences(resultRefs, stream.mappings[ruleID]) {
			return nil, fmt.Errorf("results rule %q has STIG references that do not match the data stream", ruleID)
		}
	}
	for ruleID, streamRefs := range stream.mappings {
		if !sameReferences(streamRefs, resultBenchmark.mappings[ruleID]) {
			return nil, fmt.Errorf("data stream rule %q has STIG references that do not match the results", ruleID)
		}
	}
	evidence := &ScanEvidence{
		bySTIGID:        make(map[string][]XCCDFRuleResult),
		expectedRuleIDs: make(map[string]map[string]struct{}),
		ruleReferences:  stream.mappings,
	}
	for ruleID, stigIDs := range stream.mappings {
		for _, stigID := range stigIDs {
			if evidence.expectedRuleIDs[stigID] == nil {
				evidence.expectedRuleIDs[stigID] = make(map[string]struct{})
			}
			evidence.expectedRuleIDs[stigID][ruleID] = struct{}{}
		}
	}
	for _, result := range results.RuleResults {
		for _, stigID := range stream.mappings[result.RuleID] {
			evidence.bySTIGID[stigID] = append(evidence.bySTIGID[stigID], result)
		}
	}
	return evidence, nil
}

// ResultsFor returns the scan records mapped to a DISA rule version.
func (e *ScanEvidence) ResultsFor(stigID string) []XCCDFRuleResult {
	if e == nil {
		return nil
	}
	return e.bySTIGID[stigID]
}

// DispositionFor requires every mapped SSG rule and DISA rule revision to match.
func (e *ScanEvidence) DispositionFor(stigID, disaRuleID string) (string, bool, string) {
	results := e.ResultsFor(stigID)
	if len(results) == 0 {
		return "", false, "no mapped scan results"
	}
	for ruleID := range e.expectedRuleIDs[stigID] {
		if !containsSTIGID(e.ruleReferences[ruleID], disaRuleID) {
			return "", false, "mapped SSG rule revision does not match the DISA rule"
		}
	}
	observed := make(map[string]struct{}, len(results))
	for _, result := range results {
		observed[result.RuleID] = struct{}{}
	}
	if len(observed) != len(e.expectedRuleIDs[stigID]) {
		return "", false, "results are missing for some mapped SSG rules"
	}
	status, ok := ScanDisposition(results)
	if !ok {
		return "", false, "mapped scan results conflict or have no usable disposition"
	}
	return status, true, ""
}

// ScanDisposition returns a CKLB disposition only when all supplied results agree.
func ScanDisposition(results []XCCDFRuleResult) (string, bool) {
	if len(results) == 0 {
		return "", false
	}
	first := results[0].Status
	for _, result := range results[1:] {
		if result.Status != first {
			return "", false
		}
	}
	switch first {
	case ResultPass:
		return "not_a_finding", true
	case ResultFail:
		return "open", true
	case ResultNotApplicable:
		return "not_applicable", true
	default:
		return "", false
	}
}

// FindingDetailsFor includes the source of mapped results and how they affected the disposition.
func (e *ScanEvidence) FindingDetailsFor(stigID, dispositionNote string) string {
	results := e.ResultsFor(stigID)
	if len(results) == 0 {
		return ""
	}
	rows := make([]string, 0, len(results))
	for _, result := range results {
		rows = append(rows, fmt.Sprintf("%s: %s", result.Identity, result.Status))
	}
	sort.Strings(rows)
	return "OpenSCAP results:\nDisposition source: " + dispositionNote + "\n" + strings.Join(rows, "\n")
}

func loadSSGReferences(path, benchmarkID, profileID string) (ssgBenchmark, error) {
	file, err := os.Open(path)
	if err != nil {
		return ssgBenchmark{}, fmt.Errorf("reading results data stream %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	decoder := xml.NewDecoder(file)
	root, err := nextStartElement(decoder)
	if err != nil {
		return ssgBenchmark{}, fmt.Errorf("parsing results data stream %s: %w", path, err)
	}
	if root.Name.Space != sourceDataStreamNamespace || root.Name.Local != "data-stream-collection" {
		return ssgBenchmark{}, fmt.Errorf("%s is not a SCAP source data stream collection", path)
	}
	checklistComponents := make(map[string]struct{})
	var candidates []ssgComponentBenchmark
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ssgBenchmark{}, fmt.Errorf("parsing results data stream %s: %w", path, err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch {
		case start.Name.Space == sourceDataStreamNamespace && start.Name.Local == "data-stream":
			refs, err := readChecklistComponents(decoder)
			if err != nil {
				return ssgBenchmark{}, fmt.Errorf("parsing results data stream %s: %w", path, err)
			}
			for id := range refs {
				checklistComponents[id] = struct{}{}
			}
		case start.Name.Space == sourceDataStreamNamespace && start.Name.Local == "component":
			found, err := readSSGComponent(decoder, xmlAttribute(start, "id"), benchmarkID, profileID)
			if err != nil {
				return ssgBenchmark{}, fmt.Errorf("parsing results data stream %s: %w", path, err)
			}
			candidates = append(candidates, found...)
		default:
			if err := decoder.Skip(); err != nil {
				return ssgBenchmark{}, fmt.Errorf("parsing results data stream %s: %w", path, err)
			}
		}
	}
	var selected *ssgBenchmark
	for i := range candidates {
		candidate := &candidates[i]
		if _, active := checklistComponents[candidate.componentID]; !active {
			continue
		}
		if selected != nil {
			return ssgBenchmark{}, fmt.Errorf("results data stream %s contains multiple active benchmarks %q", path, benchmarkID)
		}
		selected = &candidate.benchmark
	}
	if selected == nil {
		return ssgBenchmark{}, fmt.Errorf("results benchmark %q not found in data stream %s", benchmarkID, path)
	}
	if !selected.profileFound {
		return ssgBenchmark{}, fmt.Errorf("results profile %q not found in data stream benchmark %q", profileID, benchmarkID)
	}
	return *selected, nil
}

func readChecklistComponents(decoder *xml.Decoder) (map[string]struct{}, error) {
	refs := make(map[string]struct{})
	depth, inChecklists := 1, false
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			if depth == 1 && element.Name.Space == sourceDataStreamNamespace && element.Name.Local == "checklists" {
				inChecklists = true
			}
			if depth == 2 && inChecklists && element.Name.Space == sourceDataStreamNamespace && element.Name.Local == "component-ref" {
				for _, attribute := range element.Attr {
					if attribute.Name.Space == xlinkNamespace && attribute.Name.Local == "href" && strings.HasPrefix(attribute.Value, "#") {
						refs[strings.TrimPrefix(attribute.Value, "#")] = struct{}{}
					}
				}
			}
			depth++
		case xml.EndElement:
			if depth == 2 && element.Name.Space == sourceDataStreamNamespace && element.Name.Local == "checklists" {
				inChecklists = false
			}
			depth--
		}
	}
	return refs, nil
}

func readSSGComponent(decoder *xml.Decoder, componentID, benchmarkID, profileID string) ([]ssgComponentBenchmark, error) {
	var found []ssgComponentBenchmark
	depth := 1
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			if depth == 1 && (element.Name.Space == xccdfNamespace11 || element.Name.Space == xccdfNamespace12) && element.Name.Local == "Benchmark" && xmlAttribute(element, "id") == benchmarkID {
				benchmark, err := readSSGBenchmark(decoder, element.Name.Space, profileID)
				if err != nil {
					return nil, err
				}
				found = append(found, ssgComponentBenchmark{componentID: componentID, benchmark: benchmark})
				continue
			}
			if err := decoder.Skip(); err != nil {
				return nil, err
			}
		case xml.EndElement:
			depth--
		}
	}
	return found, nil
}

func loadResultSSGReferences(path, benchmarkID, profileID string) (ssgBenchmark, error) {
	file, err := os.Open(path)
	if err != nil {
		return ssgBenchmark{}, fmt.Errorf("reading results %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	decoder := xml.NewDecoder(file)
	root, err := nextStartElement(decoder)
	if err != nil {
		return ssgBenchmark{}, fmt.Errorf("parsing results %s: %w", path, err)
	}
	if (root.Name.Space != xccdfNamespace11 && root.Name.Space != xccdfNamespace12) || root.Name.Local != "Benchmark" || xmlAttribute(root, "id") != benchmarkID {
		return ssgBenchmark{}, fmt.Errorf("results %s has an unexpected benchmark", path)
	}
	benchmark, err := readSSGBenchmark(decoder, root.Name.Space, profileID)
	if err != nil {
		return ssgBenchmark{}, fmt.Errorf("parsing results %s: %w", path, err)
	}
	return benchmark, nil
}

func nextStartElement(decoder *xml.Decoder) (xml.StartElement, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if start, ok := token.(xml.StartElement); ok {
			return start, nil
		}
	}
}

func readSSGBenchmark(decoder *xml.Decoder, namespace, expectedProfile string) (ssgBenchmark, error) {
	benchmark := ssgBenchmark{mappings: make(map[string][]string)}
	depth := 1
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return ssgBenchmark{}, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch {
			case depth == 1 && element.Name.Space == namespace && element.Name.Local == "version":
				var text string
				if err := decoder.DecodeElement(&text, &element); err != nil {
					return ssgBenchmark{}, err
				}
				benchmark.version = normalizeWhitespace(text)
			case depth == 1 && element.Name.Space == namespace && element.Name.Local == "Profile":
				if xmlAttribute(element, "id") != expectedProfile {
					if err := decoder.Skip(); err != nil {
						return ssgBenchmark{}, err
					}
					continue
				}
				if benchmark.profileFound {
					return ssgBenchmark{}, fmt.Errorf("duplicate scan profile %q", expectedProfile)
				}
				benchmark.profileFound = true
				benchmark.profileSettings, err = readSSGProfileSettings(decoder, element)
				if err != nil {
					return ssgBenchmark{}, err
				}
			case element.Name.Space == namespace && element.Name.Local == "Rule":
				var rule ssgRule
				if err := decoder.DecodeElement(&rule, &element); err != nil {
					return ssgBenchmark{}, err
				}
				if !strings.HasPrefix(rule.ID, ssgRulePrefix) {
					continue
				}
				for _, reference := range rule.References {
					if reference.XMLName.Space != namespace || !isSTIGReference(reference.Href) {
						continue
					}
					for _, stigID := range strings.Split(reference.Value, ",") {
						stigID = strings.TrimSpace(stigID)
						if stigID != "" && !containsSTIGID(benchmark.mappings[rule.ID], stigID) {
							benchmark.mappings[rule.ID] = append(benchmark.mappings[rule.ID], stigID)
						}
					}
				}
			default:
				depth++
			}
		case xml.EndElement:
			depth--
		}
	}
	return benchmark, nil
}

func readSSGProfileSettings(decoder *xml.Decoder, profile xml.StartElement) ([]string, error) {
	settings := []string{xmlAttributesKey(profile.Attr)}
	depth := 1
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			if depth == 1 && element.Name.Space == profile.Name.Space {
				switch element.Name.Local {
				case "select", "set-value", "refine-value", "refine-rule", "version":
					var value string
					if err := decoder.DecodeElement(&value, &element); err != nil {
						return nil, err
					}
					settings = append(settings, fmt.Sprintf("%s %s %q", element.Name.Local, xmlAttributesKey(element.Attr), strings.TrimSpace(value)))
					continue
				}
			}
			depth++
		case xml.EndElement:
			depth--
		}
	}
	return settings, nil
}

func xmlAttributesKey(attributes []xml.Attr) string {
	parts := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		parts = append(parts, fmt.Sprintf("{%s}%s=%q", attribute.Name.Space, attribute.Name.Local, attribute.Value))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func sameReferences(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, reference := range a {
		if !containsSTIGID(b, reference) {
			return false
		}
	}
	return true
}

func containsSTIGID(ids []string, candidate string) bool {
	for _, id := range ids {
		if id == candidate {
			return true
		}
	}
	return false
}

func isSTIGReference(href string) bool {
	parsed, err := url.Parse(href)
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "cyber.mil", "www.cyber.mil", "public.cyber.mil":
		return strings.HasPrefix(parsed.Path, "/stigs/")
	default:
		return false
	}
}

func xmlAttribute(element xml.StartElement, name string) string {
	for _, attribute := range element.Attr {
		if attribute.Name.Local == name && attribute.Name.Space == "" {
			return attribute.Value
		}
	}
	return ""
}
