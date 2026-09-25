// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	xccdfNamespace11 = "http://checklists.nist.gov/xccdf/1.1"
	xccdfNamespace12 = "http://checklists.nist.gov/xccdf/1.2"
)

// ResultStatus is an XCCDF rule-result disposition.
type ResultStatus string

const (
	ResultPass          ResultStatus = "pass"
	ResultFail          ResultStatus = "fail"
	ResultError         ResultStatus = "error"
	ResultUnknown       ResultStatus = "unknown"
	ResultNotApplicable ResultStatus = "notapplicable"
	ResultNotChecked    ResultStatus = "notchecked"
	ResultNotSelected   ResultStatus = "notselected"
	ResultInformational ResultStatus = "informational"
	ResultFixed         ResultStatus = "fixed"
)

var orderedResultStatuses = []ResultStatus{
	ResultPass,
	ResultFail,
	ResultError,
	ResultUnknown,
	ResultNotApplicable,
	ResultNotChecked,
	ResultNotSelected,
	ResultInformational,
	ResultFixed,
}

// XCCDFResultSet contains the single TestResult extracted from an XCCDF Benchmark.
type XCCDFResultSet struct {
	SourcePath       string
	BenchmarkID      string
	BenchmarkVersion string
	TestResultID     string
	ProfileID        string
	StartTime        string
	EndTime          string
	Targets          []string
	RuleResults      map[string]XCCDFRuleResult
}

// XCCDFRuleResult is one uniquely identifiable XCCDF rule-result record.
type XCCDFRuleResult struct {
	Identity string
	Status   ResultStatus
}

// ChangeClassification describes how a rule disposition changed.
type ChangeClassification string

const (
	Regression       ChangeClassification = "regression"
	Improvement      ChangeClassification = "improvement"
	Reclassification ChangeClassification = "reclassification"
)

// ResultChange is a changed rule-result record between two scans.
type ResultChange struct {
	Identity       string
	BaseStatus     ResultStatus
	NewStatus      ResultStatus
	Classification ChangeClassification
}

// XCCDFComparison is the validated comparison of two result sets.
type XCCDFComparison struct {
	Base             *XCCDFResultSet
	New              *XCCDFResultSet
	Changes          []ResultChange
	UnchangedCount   int
	RegressionCount  int
	ImprovementCount int
	ReclassifyCount  int
}

// HasRegressions reports whether the candidate contains regressions.
func (c *XCCDFComparison) HasRegressions() bool {
	return c.RegressionCount > 0
}

// IncompatibleResultSetsError indicates that scans evaluated different rule-result identities.
type IncompatibleResultSetsError struct {
	BaseOnly []string
	NewOnly  []string
	Metadata []string
}

func (e *IncompatibleResultSetsError) Error() string {
	parts := []string{"XCCDF result sets are not comparable"}
	if len(e.BaseOnly) > 0 {
		parts = append(parts, fmt.Sprintf("present only in base: %s", strings.Join(e.BaseOnly, ", ")))
	}
	if len(e.NewOnly) > 0 {
		parts = append(parts, fmt.Sprintf("present only in new: %s", strings.Join(e.NewOnly, ", ")))
	}
	if len(e.Metadata) > 0 {
		parts = append(parts, strings.Join(e.Metadata, "; "))
	}
	return strings.Join(parts, "; ")
}

type xccdfResultBenchmark struct {
	XMLName     xml.Name          `xml:"Benchmark"`
	ID          string            `xml:"id,attr"`
	Title       xccdfText         `xml:"title"`
	Version     xccdfText         `xml:"version"`
	TestResults []xccdfTestResult `xml:"TestResult"`
}

type xccdfTestResult struct {
	XMLName     xml.Name             `xml:"TestResult"`
	ID          string               `xml:"id,attr"`
	StartTime   string               `xml:"start-time,attr"`
	EndTime     string               `xml:"end-time,attr"`
	Title       xccdfText            `xml:"title"`
	Profile     xccdfProfileRef      `xml:"profile"`
	Targets     []xccdfText          `xml:"target"`
	RuleResults []xccdfXMLRuleResult `xml:"rule-result"`
}

type xccdfText struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type xccdfProfileRef struct {
	XMLName xml.Name `xml:"profile"`
	IDRef   string   `xml:"idref,attr"`
}

type xccdfXMLRuleResult struct {
	XMLName   xml.Name        `xml:"rule-result"`
	IDRef     string          `xml:"idref,attr"`
	Result    xccdfText       `xml:"result"`
	Instances []xccdfInstance `xml:"instance"`
}

type xccdfInstance struct {
	XMLName       xml.Name `xml:"instance"`
	Context       string   `xml:"context,attr"`
	ParentContext string   `xml:"parentContext,attr"`
	Text          string   `xml:",chardata"`
}

// LoadXCCDFResults parses one XCCDF 1.1 or 1.2 Benchmark containing exactly one TestResult.
func LoadXCCDFResults(path string) (*XCCDFResultSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var benchmark xccdfResultBenchmark
	if err := xml.Unmarshal(data, &benchmark); err != nil {
		return nil, fmt.Errorf("parsing XCCDF results: %w", err)
	}
	namespace := benchmark.XMLName.Space
	if benchmark.XMLName.Local != "Benchmark" || (namespace != xccdfNamespace11 && namespace != xccdfNamespace12) {
		return nil, fmt.Errorf("%s is not an XCCDF 1.1 or 1.2 Benchmark", path)
	}
	if strings.TrimSpace(benchmark.ID) == "" {
		return nil, fmt.Errorf("%s Benchmark is missing id", path)
	}
	if err := validateXCCDFNamespaces(benchmark, namespace); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(benchmark.TestResults) != 1 {
		return nil, fmt.Errorf("%s must contain exactly one TestResult; found %d", path, len(benchmark.TestResults))
	}
	testResult := benchmark.TestResults[0]
	if strings.TrimSpace(testResult.ID) == "" {
		return nil, fmt.Errorf("%s TestResult is missing id", path)
	}
	set := &XCCDFResultSet{
		SourcePath:       path,
		BenchmarkID:      strings.TrimSpace(benchmark.ID),
		BenchmarkVersion: normalizeWhitespace(benchmark.Version.Value),
		TestResultID:     strings.TrimSpace(testResult.ID),
		ProfileID:        strings.TrimSpace(testResult.Profile.IDRef),
		StartTime:        strings.TrimSpace(testResult.StartTime),
		EndTime:          strings.TrimSpace(testResult.EndTime),
		Targets:          normalizedTargets(testResult.Targets),
		RuleResults:      map[string]XCCDFRuleResult{},
	}
	for _, raw := range testResult.RuleResults {
		ruleID := strings.TrimSpace(raw.IDRef)
		if ruleID == "" {
			return nil, fmt.Errorf("%s contains a rule-result without idref", path)
		}
		status, err := parseResultStatus(raw.Result.Value)
		if err != nil {
			return nil, fmt.Errorf("%s rule-result %q: %w", path, ruleID, err)
		}
		instance := canonicalInstance(raw.Instances)
		identity := ruleID
		if instance != "" {
			identity += " [" + instance + "]"
		}
		if _, exists := set.RuleResults[identity]; exists {
			return nil, fmt.Errorf("%s contains ambiguous duplicate rule-result identity %q", path, identity)
		}
		set.RuleResults[identity] = XCCDFRuleResult{Identity: identity, Status: status}
	}
	return set, nil
}

func validateXCCDFNamespaces(benchmark xccdfResultBenchmark, namespace string) error {
	if err := validateXCCDFTextNamespace("Benchmark title", benchmark.Title, namespace); err != nil {
		return err
	}
	if err := validateXCCDFTextNamespace("Benchmark version", benchmark.Version, namespace); err != nil {
		return err
	}
	for _, testResult := range benchmark.TestResults {
		if testResult.XMLName.Space != namespace {
			return fmt.Errorf("TestResult is not in the Benchmark namespace")
		}
		if err := validateXCCDFTextNamespace("TestResult title", testResult.Title, namespace); err != nil {
			return err
		}
		if testResult.Profile.XMLName.Local != "" && testResult.Profile.XMLName.Space != namespace {
			return fmt.Errorf("profile is not in the Benchmark namespace")
		}
		for _, target := range testResult.Targets {
			if err := validateXCCDFTextNamespace("target", target, namespace); err != nil {
				return err
			}
		}
		for _, ruleResult := range testResult.RuleResults {
			if ruleResult.XMLName.Space != namespace {
				return fmt.Errorf("rule-result is not in the Benchmark namespace")
			}
			if ruleResult.Result.XMLName.Space != namespace {
				return fmt.Errorf("result is not in the Benchmark namespace")
			}
			for _, instance := range ruleResult.Instances {
				if instance.XMLName.Space != namespace {
					return fmt.Errorf("instance is not in the Benchmark namespace")
				}
			}
		}
	}
	return nil
}

func validateXCCDFTextNamespace(name string, value xccdfText, namespace string) error {
	if value.XMLName.Local != "" && value.XMLName.Space != namespace {
		return fmt.Errorf("%s is not in the Benchmark namespace", name)
	}
	return nil
}

// CompareXCCDFResults validates equivalent identities and classifies disposition changes.
func CompareXCCDFResults(base, newResults *XCCDFResultSet) (*XCCDFComparison, error) {
	if base == nil || newResults == nil {
		return nil, fmt.Errorf("both XCCDF result sets are required")
	}
	baseOnly, newOnly := resultSetDifferences(base, newResults)
	metadata := resultSetMetadataDifferences(base, newResults)
	if len(baseOnly) > 0 || len(newOnly) > 0 || len(metadata) > 0 {
		return nil, &IncompatibleResultSetsError{
			BaseOnly: baseOnly,
			NewOnly:  newOnly,
			Metadata: metadata,
		}
	}
	comparison := &XCCDFComparison{Base: base, New: newResults}
	for _, identity := range sortedRuleResultIdentities(base.RuleResults) {
		before, after := base.RuleResults[identity], newResults.RuleResults[identity]
		if before.Status == after.Status {
			comparison.UnchangedCount++
			continue
		}
		kind := classifyStatusChange(before.Status, after.Status)
		comparison.Changes = append(comparison.Changes, ResultChange{
			Identity:       identity,
			BaseStatus:     before.Status,
			NewStatus:      after.Status,
			Classification: kind,
		})
		switch kind {
		case Regression:
			comparison.RegressionCount++
		case Improvement:
			comparison.ImprovementCount++
		case Reclassification:
			comparison.ReclassifyCount++
		}
	}
	return comparison, nil
}

// RenderXCCDFComparison creates stable human-readable comparison evidence.
func RenderXCCDFComparison(comparison *XCCDFComparison) string {
	var builder strings.Builder
	builder.WriteString("XCCDF Result Comparison\n\n")
	writeResultMetadata(&builder, "Base", comparison.Base)
	builder.WriteByte('\n')
	writeResultMetadata(&builder, "New", comparison.New)
	builder.WriteByte('\n')
	writeStatusSummary(&builder, "Base", comparison.Base)
	builder.WriteByte('\n')
	writeStatusSummary(&builder, "New", comparison.New)
	builder.WriteByte('\n')
	fmt.Fprintln(&builder, "Comparison summary:")
	fmt.Fprintf(
		&builder,
		"  unchanged:         %d\n  regressions:       %d\n  improvements:      %d\n  reclassifications: %d\n  changed:           %d\n",
		comparison.UnchangedCount,
		comparison.RegressionCount,
		comparison.ImprovementCount,
		comparison.ReclassifyCount,
		len(comparison.Changes),
	)
	for _, kind := range []ChangeClassification{Regression, Improvement, Reclassification} {
		changes := changesOfType(comparison.Changes, kind)
		if len(changes) == 0 {
			continue
		}
		fmt.Fprintf(&builder, "\n%s (%d):\n", strings.ToUpper(string(kind))+"S", len(changes))
		for _, change := range changes {
			fmt.Fprintf(&builder, "  %s\n    base=%s  new=%s\n", change.Identity, change.BaseStatus, change.NewStatus)
		}
	}
	if comparison.HasRegressions() {
		fmt.Fprintf(&builder, "\nFAIL: %d XCCDF regression(s) detected.\n", comparison.RegressionCount)
	} else {
		builder.WriteString("\nPASS: no XCCDF regressions detected.\n")
	}
	return builder.String()
}

func parseResultStatus(value string) (ResultStatus, error) {
	status := ResultStatus(strings.TrimSpace(value))
	if _, ok := resultStatusTier(status); !ok {
		return "", fmt.Errorf("unsupported result status %q", strings.TrimSpace(value))
	}
	return status, nil
}

func resultStatusTier(status ResultStatus) (int, bool) {
	switch status {
	case ResultFail, ResultError:
		return 0, true
	case ResultUnknown, ResultNotChecked:
		return 1, true
	case ResultPass, ResultFixed, ResultNotApplicable, ResultInformational:
		return 2, true
	case ResultNotSelected:
		return 3, true
	default:
		return 0, false
	}
}

func classifyStatusChange(base, newStatus ResultStatus) ChangeClassification {
	if base == ResultNotSelected || newStatus == ResultNotSelected {
		return Reclassification
	}
	baseTier, _ := resultStatusTier(base)
	newTier, _ := resultStatusTier(newStatus)
	if newTier < baseTier {
		return Regression
	}
	if newTier > baseTier {
		return Improvement
	}
	return Reclassification
}

func canonicalInstance(instances []xccdfInstance) string {
	parts := make([]string, 0, len(instances))
	for _, instance := range instances {
		context := normalizeWhitespace(instance.Context)
		if context == "" {
			context = "undefined"
		}
		parts = append(parts, fmt.Sprintf(
			"name=%q,context=%q,parent=%q",
			normalizeWhitespace(instance.Text),
			context,
			normalizeWhitespace(instance.ParentContext),
		))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func normalizedTargets(targets []xccdfText) []string {
	result := make([]string, 0, len(targets))
	for _, target := range targets {
		if value := normalizeWhitespace(target.Value); value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func resultSetDifferences(base, newResults *XCCDFResultSet) ([]string, []string) {
	baseOnly, newOnly := []string{}, []string{}
	for identity := range base.RuleResults {
		if _, found := newResults.RuleResults[identity]; !found {
			baseOnly = append(baseOnly, identity)
		}
	}
	for identity := range newResults.RuleResults {
		if _, found := base.RuleResults[identity]; !found {
			newOnly = append(newOnly, identity)
		}
	}
	sort.Strings(baseOnly)
	sort.Strings(newOnly)
	return baseOnly, newOnly
}

func resultSetMetadataDifferences(base, newResults *XCCDFResultSet) []string {
	differences := []string{}
	for _, field := range []struct {
		name     string
		base     string
		newValue string
	}{
		{"benchmark ID", base.BenchmarkID, newResults.BenchmarkID},
		{"benchmark version", base.BenchmarkVersion, newResults.BenchmarkVersion},
		{"profile ID", base.ProfileID, newResults.ProfileID},
	} {
		if field.base != field.newValue {
			differences = append(differences, fmt.Sprintf(
				"%s differs (base=%q, new=%q)",
				field.name,
				field.base,
				field.newValue,
			))
		}
	}
	return differences
}

func sortedRuleResultIdentities(results map[string]XCCDFRuleResult) []string {
	identities := make([]string, 0, len(results))
	for identity := range results {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	return identities
}

func changesOfType(changes []ResultChange, kind ChangeClassification) []ResultChange {
	filtered := []ResultChange{}
	for _, change := range changes {
		if change.Classification == kind {
			filtered = append(filtered, change)
		}
	}
	return filtered
}

func writeResultMetadata(builder *strings.Builder, label string, resultSet *XCCDFResultSet) {
	fmt.Fprintf(
		builder,
		"%s results: %s\n  benchmark: %s\n  benchmark version: %s\n  test result: %s\n  profile: %s\n  targets: %s\n  start: %s\n  end: %s\n",
		label,
		resultSet.SourcePath,
		displayMetadata(resultSet.BenchmarkID),
		displayMetadata(resultSet.BenchmarkVersion),
		displayMetadata(resultSet.TestResultID),
		displayMetadata(resultSet.ProfileID),
		displayMetadata(strings.Join(resultSet.Targets, ", ")),
		displayMetadata(resultSet.StartTime),
		displayMetadata(resultSet.EndTime),
	)
}

func writeStatusSummary(builder *strings.Builder, label string, resultSet *XCCDFResultSet) {
	counts := map[ResultStatus]int{}
	for _, result := range resultSet.RuleResults {
		counts[result.Status]++
	}
	fmt.Fprintf(
		builder,
		"%s summary: %d total rule-result(s), %d in profile scope\n",
		label,
		len(resultSet.RuleResults),
		len(resultSet.RuleResults)-counts[ResultNotSelected],
	)
	for _, status := range orderedResultStatuses {
		fmt.Fprintf(builder, "  %s: %d\n", status, counts[status])
	}
}

func normalizeWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func displayMetadata(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
