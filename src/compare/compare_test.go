// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package compare

import (
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

// Common test data reused across multiple tests.
var (
	// Vulnerabilities used for table rows and comparison tests.
	commonFixedVuln = cyclonedx.Vulnerability{
		ID: "VULN-FIX",
		Affects: &[]cyclonedx.Affects{
			{Ref: "pkgFix@v1"},
		},
		Ratings: &[]cyclonedx.VulnerabilityRating{
			{Severity: "medium"},
		},
		Source: &cyclonedx.Source{
			URL: "http://example.com/fix",
		},
	}
	commonExistVuln = cyclonedx.Vulnerability{
		ID: "VULN-EXIST",
		Affects: &[]cyclonedx.Affects{
			{Ref: "pkgExist@v1"},
		},
		Ratings: &[]cyclonedx.VulnerabilityRating{
			{Severity: "high"},
		},
		Source: &cyclonedx.Source{
			URL: "http://example.com/exist",
		},
	}
	commonNewVuln = cyclonedx.Vulnerability{
		ID: "VULN-NEW",
		Affects: &[]cyclonedx.Affects{
			{Ref: "pkgNew@v1"},
		},
		Ratings: &[]cyclonedx.VulnerabilityRating{
			{Severity: "low"},
		},
		Source: &cyclonedx.Source{
			URL: "http://example.com/new",
		},
	}

	// BOMs for comparison tests.
	commonBaseScan = cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Name:    "BaseComponent",
				Version: "1.0",
			},
		},
		Vulnerabilities: &[]cyclonedx.Vulnerability{commonFixedVuln, commonExistVuln},
	}
	commonNewBaseScan = cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Name:    "BaseComponent",
				Version: "2.0",
			},
		},
		Vulnerabilities: &[]cyclonedx.Vulnerability{commonExistVuln, commonNewVuln},
	}

	// Vulnerabilities reused in getVulnByUID tests.
	commonVuln1 = cyclonedx.Vulnerability{
		ID: "VULN-1",
		Affects: &[]cyclonedx.Affects{
			{Ref: "pkgA@v1.0.0"},
		},
		Ratings: &[]cyclonedx.VulnerabilityRating{{Severity: "high"}},
		Source:  &cyclonedx.Source{URL: "http://example.com/vuln1"},
	}
	commonVuln2 = cyclonedx.Vulnerability{
		ID: "VULN-2",
		Affects: &[]cyclonedx.Affects{
			{Ref: "pkgB@v2.0.0"},
		},
		Ratings: &[]cyclonedx.VulnerabilityRating{{Severity: "medium"}},
		Source:  &cyclonedx.Source{URL: "http://example.com/vuln2"},
	}
)

func TestSetupTables(t *testing.T) {
	newBuilder := &strings.Builder{}
	fixedBuilder := &strings.Builder{}
	existingBuilder := &strings.Builder{}

	newTable, fixedTable, existingTable := setupTables(newBuilder, fixedBuilder, existingBuilder)
	if newTable == nil || fixedTable == nil || existingTable == nil {
		t.Fatal("Expected all returned tables to be non-nil")
	}

	dummyRow := []string{"VULN-123", "high", "http://example.com"}
	expectedHeaders := []string{"ID", "Severity", "URL"}

	newTable.Append(dummyRow)
	fixedTable.Append(dummyRow)
	existingTable.Append(dummyRow)

	newTable.Render()
	fixedTable.Render()
	existingTable.Render()

	outputs := map[string]string{
		"new":      newBuilder.String(),
		"fixed":    fixedBuilder.String(),
		"existing": existingBuilder.String(),
	}

	for tableName, output := range outputs {
		for _, header := range expectedHeaders {
			if !strings.Contains(strings.ToLower(output), strings.ToLower(header)) {
				t.Errorf("Rendered %s table output does not contain header %q", tableName, header)
			}
		}
		for _, field := range dummyRow {
			if !strings.Contains(strings.ToLower(output), strings.ToLower(field)) {
				t.Errorf("Rendered %s table output does not contain dummy field %q", tableName, field)
			}
		}
		if strings.Contains(strings.ToLower(output), "-+-") {
			t.Errorf("Rendered %s table output is using + as a center seperator", tableName)
		}
	}
}

func TestGenerateTableRows(t *testing.T) {
	// Use the common vulnerabilities.
	vulnStatus := map[string]int{
		getUniqueVulnId(commonFixedVuln): 2, // fixed
		getUniqueVulnId(commonExistVuln): 1, // existing
		getUniqueVulnId(commonNewVuln):   0, // new
	}

	baseVulns := []cyclonedx.Vulnerability{commonFixedVuln, commonExistVuln}
	newVulns := []cyclonedx.Vulnerability{commonExistVuln, commonNewVuln}

	newRows, fixedRows, existRows, err := generateTableRows(baseVulns, newVulns, vulnStatus)
	if err != nil {
		t.Fatalf("Expected no error but got: %v", err)
	}

	if len(newRows) != 1 {
		t.Errorf("Expected 1 new vulnerability row, got %d", len(newRows))
	} else {
		row := newRows[0]
		if row[0] != commonNewVuln.ID {
			t.Errorf("Expected new row ID %q, got %q", commonNewVuln.ID, row[0])
		}
		if row[1] != "low" {
			t.Errorf("Expected new row severity 'low', got %q", row[1])
		}
		if row[2] != commonNewVuln.Source.URL {
			t.Errorf("Expected new row Source URL %q, got %q", commonNewVuln.Source.URL, row[2])
		}
	}

	if len(fixedRows) != 1 {
		t.Errorf("Expected 1 fixed vulnerability row, got %d", len(fixedRows))
	} else {
		row := fixedRows[0]
		if row[0] != commonFixedVuln.ID {
			t.Errorf("Expected fixed row ID %q, got %q", commonFixedVuln.ID, row[0])
		}
		if row[1] != "medium" {
			t.Errorf("Expected fixed row severity 'medium', got %q", row[1])
		}
		if row[2] != commonFixedVuln.Source.URL {
			t.Errorf("Expected fixed row Source URL %q, got %q", commonFixedVuln.Source.URL, row[2])
		}
	}

	if len(existRows) != 1 {
		t.Errorf("Expected 1 existing vulnerability row, got %d", len(existRows))
	} else {
		row := existRows[0]
		if row[0] != commonExistVuln.ID {
			t.Errorf("Expected existing row ID %q, got %q", commonExistVuln.ID, row[0])
		}
		if row[1] != "high" {
			t.Errorf("Expected existing row severity 'high', got %q", row[1])
		}
		if row[2] != commonExistVuln.Source.URL {
			t.Errorf("Expected existing row Source URL %q, got %q", commonExistVuln.Source.URL, row[2])
		}
	}
}

func TestLoadScanJson_Success(t *testing.T) {
	filePath := "../test/scans/busybox.json"
	bom, err := loadScanJson(filePath)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if bom.Vulnerabilities == nil {
		t.Errorf("Expected Vulnerabilities field to be non-nil")
	}
}

func TestLoadScanJson_FileNotFound(t *testing.T) {
	_, err := loadScanJson("nonexistent_file.json")
	if err == nil {
		t.Fatal("Expected error for nonexistent file, got nil")
	}
}

func TestLoadScanJson_NoVulnerabilities(t *testing.T) {
	filepath := "../test/scans/busybox_no_vulns.json"
	bom, err := loadScanJson(filepath)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if bom.Vulnerabilities == nil {
		t.Errorf("Expected Vulnerabilities field to be non-nil even if empty")
	}
	if len(*bom.Vulnerabilities) != 0 {
		t.Errorf("Expected Vulnerabilities to be empty, got %d items", len(*bom.Vulnerabilities))
	}
}


func TestGetUniqueVulnId(t *testing.T) {
	vuln := cyclonedx.Vulnerability{
		ID: "VULN-TEST",
		Affects: &[]cyclonedx.Affects{
			{Ref: "pkgTest@v2.3.4"},
		},
		Ratings: &[]cyclonedx.VulnerabilityRating{
			{Severity: "high"},
		},
		Source: &cyclonedx.Source{
			URL: "http://example.com/test",
		},
	}

	expected := "VULN-TEST|pkgTest"
	result := getUniqueVulnId(vuln)
	if result != expected {
		t.Errorf("Expected unique vuln id %q; got %q", expected, result)
	}
}

func TestGetUniqueVulnId_MultipleAffects(t *testing.T) {
	vuln := cyclonedx.Vulnerability{
		ID: "VULN-MULTI",
		Affects: &[]cyclonedx.Affects{
			{Ref: "firstPkg@v1.0.0"},
			{Ref: "secondPkg@v2.0.0"},
		},
		Ratings: &[]cyclonedx.VulnerabilityRating{
			{Severity: "medium"},
		},
		Source: &cyclonedx.Source{
			URL: "http://example.com/multi",
		},
	}

	expected := "VULN-MULTI|firstPkg"
	result := getUniqueVulnId(vuln)
	if result != expected {
		t.Errorf("Expected unique vuln id %q; got %q", expected, result)
	}
}

func TestGetVulnByUID_Success(t *testing.T) {
	vulns := []cyclonedx.Vulnerability{commonVuln1, commonVuln2}
	uid := getUniqueVulnId(commonVuln2)
	foundVuln, err := getVulnByUID(uid, vulns)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if foundVuln.ID != commonVuln2.ID {
		t.Errorf("Expected vulnerability ID %q, got %q", commonVuln2.ID, foundVuln.ID)
	}
}

func TestGetVulnByUID_NotFound(t *testing.T) {
	vulns := []cyclonedx.Vulnerability{commonVuln1}
	_, err := getVulnByUID("NON-EXISTENT|pkgX", vulns)
	if err == nil {
		t.Fatal("Expected error for missing vulnerability, got nil")
	}
}

func TestSortRows(t *testing.T) {
	rows := [][]string{
		{"ID1", "medium", "http://example.com", "http://advise.com"},
		{"ID2", "critical", "http://example.com", "http://advise.com"},
		{"ID3", "high", "http://example.com", "http://advise.com"},
		{"ID4", "unknown", "http://example.com", "http://advise.com"},
		{"ID5", "low", "http://example.com", "http://advise.com"},
		{"ID6", "none", "http://example.com", "http://advise.com"},
		{"ID7", "notdefined", "http://example.com", "http://advise.com"},
	}

	expectedOrder := []string{"ID2", "ID3", "ID1", "ID5", "ID6", "ID4", "ID7"}
	sortedRows := sortRows(rows)
	if len(sortedRows) != len(expectedOrder) {
		t.Fatalf("Expected %d rows after sorting, got %d", len(expectedOrder), len(sortedRows))
	}
	for i, row := range sortedRows {
		if row[0] != expectedOrder[i] {
			t.Errorf("At index %d: expected row with ID %q, got %q", i, expectedOrder[i], row[0])
		}
	}
}

func TestSortRows_Empty(t *testing.T) {
	var rows [][]string
	sortedRows := sortRows(rows)
	if len(sortedRows) != 0 {
		t.Errorf("Expected empty slice after sorting, got %d elements", len(sortedRows))
	}
}

func TestGenerateComparisonMarkdown_Success(t *testing.T) {
	// Use the common BOMs.
	vulnStatus := GenerateComparisonMap(commonBaseScan, commonNewBaseScan)
	markdown, err := GenerateComparisonMarkdown(commonBaseScan, commonNewBaseScan, vulnStatus)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !strings.Contains(markdown, "New vulnerabilities: 1") {
		t.Errorf("Expected markdown to contain new vulnerabilities count '1'")
	}
	if !strings.Contains(markdown, "Fixed vulnerabilities: 1") {
		t.Errorf("Expected markdown to contain fixed vulnerabilities count '1'")
	}
	if !strings.Contains(markdown, "Existing vulnerabilities: 1") {
		t.Errorf("Expected markdown to contain existing vulnerabilities count '1'")
	}
	if !strings.Contains(markdown, "BaseComponent `1.0` -> `2.0`") {
		t.Errorf("Expected markdown to contain component names and versions")
	}
	if !strings.Contains(markdown, "<summary>New vulnerabilities</summary>") {
		t.Errorf("Expected markdown to contain new vulnerabilities details section")
	}
	if !strings.Contains(markdown, "<summary>Fixed vulnerabilities</summary>") {
		t.Errorf("Expected markdown to contain fixed vulnerabilities details section")
	}
	if !strings.Contains(markdown, "<summary>Existing vulnerabilities</summary>") {
		t.Errorf("Expected markdown to contain existing vulnerabilities details section")
	}
}

func TestGenerateComparisonMarkdown_EmptyVulnerabilities(t *testing.T) {
	emptyBase := cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Name:    "Base",
				Version: "1.0",
			},
		},
		Vulnerabilities: &[]cyclonedx.Vulnerability{},
	}
	emptyNew := cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Name:    "New",
				Version: "1.0",
			},
		},
		Vulnerabilities: &[]cyclonedx.Vulnerability{},
	}
	vulnStatus := GenerateComparisonMap(emptyBase, emptyNew)
	markdown, err := GenerateComparisonMarkdown(emptyBase, emptyNew, vulnStatus)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !strings.Contains(markdown, "New vulnerabilities: 0") {
		t.Errorf("Expected markdown to show 0 new vulnerabilities")
	}
	if !strings.Contains(markdown, "Fixed vulnerabilities: 0") {
		t.Errorf("Expected markdown to show 0 fixed vulnerabilities")
	}
	if !strings.Contains(markdown, "Existing vulnerabilities: 0") {
		t.Errorf("Expected markdown to show 0 existing vulnerabilities")
	}
}

func TestGenerateComparisonCounts(t *testing.T) {
	vulnStatus := map[string]int{
		"VULN-NEW|pkgNew":   0, // new
		"VULN-EXIST|pkgExist": 1, // existing
		"VULN-FIX|pkgFix":   2, // fixed
	}

	counts := GenerateComparisonCounts(vulnStatus)
	expectedOutput := "New vulnerabilities: 1\nFixed vulnerabilities: 1\nExisting vulnerabilities: 1\n"

	if counts != expectedOutput {
		t.Errorf("Expected counts output:\n%s\nGot:\n%s", expectedOutput, counts)
	}
}