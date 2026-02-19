// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package compare

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

func LoadScans(basePath string, newPath string) (cyclonedx.BOM, cyclonedx.BOM, error) {
	baseScan, err := loadScanJson(basePath)
	if err != nil {
		return cyclonedx.BOM{}, cyclonedx.BOM{}, err
	}

	newScan, err := loadScanJson(newPath)
	if err != nil {
		return cyclonedx.BOM{}, cyclonedx.BOM{}, err
	}

	return baseScan, newScan, nil
}

func GenerateComparisonMap(baseScan cyclonedx.BOM, newScan cyclonedx.BOM) map[string]int {
	// matchStatus : 0 = new, 1 = existing, 2 = fixed
	vulnStatus := make(map[string]int)

	for _, baseVuln := range *baseScan.Vulnerabilities {
		vulnStatus[getUniqueVulnId(baseVuln)] = 2
	}

	for _, newVuln := range *newScan.Vulnerabilities {
		vulnUID := getUniqueVulnId(newVuln)
		if _, ok := vulnStatus[vulnUID]; ok {
			vulnStatus[vulnUID] = 1
		} else {
			vulnStatus[vulnUID] = 0
		}
	}

	return vulnStatus
}

func GenerateComparisonMarkdown(baseScan cyclonedx.BOM, newScan cyclonedx.BOM, vulnStatus map[string]int) (string, error) {
	newCount := 0
	existingCount := 0
	fixedCount := 0

	for _, status := range vulnStatus {
		switch status {
		case 0:
			newCount++
		case 1:
			existingCount++
		case 2:
			fixedCount++
		}
	}

	var outputBuilder strings.Builder

	if newScan.Metadata.Component.Name == baseScan.Metadata.Component.Name {
		fmt.Fprintf(&outputBuilder,
			"### %s `%s` -> `%s`\n\n",
			baseScan.Metadata.Component.Name,
			baseScan.Metadata.Component.Version,
			newScan.Metadata.Component.Version,
		)
	} else {
		fmt.Fprintf(&outputBuilder,
			"### `%s:%s` -> `%s:%s`\n\n",
			baseScan.Metadata.Component.Name,
			baseScan.Metadata.Component.Version,
			newScan.Metadata.Component.Name,
			newScan.Metadata.Component.Version,
		)
	}

	outputBuilder.WriteString(fmt.Sprintf("New vulnerabilities: %d\n", newCount))
	outputBuilder.WriteString(fmt.Sprintf("Fixed vulnerabilities: %d\n", fixedCount))
	outputBuilder.WriteString(fmt.Sprintf("Existing vulnerabilities: %d\n\n", existingCount))

	newVulnTableString := &strings.Builder{}
	fixedVulnTableString := &strings.Builder{}
	existingVulnTableString := &strings.Builder{}

	newVulnTable, fixedVulnTable, existingVulnTable := setupTables(newVulnTableString, fixedVulnTableString, existingVulnTableString)

	newVulnRows, fixedVulnRows, existingVulnRows, err := generateTableRows(*baseScan.Vulnerabilities, *newScan.Vulnerabilities, vulnStatus)
	if err != nil {
		return "", err
	}

	newVulnRows = sortRows(newVulnRows)
	fixedVulnRows = sortRows(fixedVulnRows)
	existingVulnRows = sortRows(existingVulnRows)

	if err := newVulnTable.Bulk(newVulnRows); err != nil {
		return "", err
	}
	if err := fixedVulnTable.Bulk(fixedVulnRows); err != nil {
		return "", err
	}
	if err := existingVulnTable.Bulk(existingVulnRows); err != nil {
		return "", err
	}

	outputBuilder.WriteString("<details>\n")
	outputBuilder.WriteString("<summary>New vulnerabilities</summary>\n\n")

	if err := newVulnTable.Render(); err != nil {
		return "", err
	}

	outputBuilder.WriteString(newVulnTableString.String())
	outputBuilder.WriteString("\n</details>\n")

	outputBuilder.WriteString("<details>\n")
	outputBuilder.WriteString("<summary>Fixed vulnerabilities</summary>\n\n")

	if err := fixedVulnTable.Render(); err != nil {
		return "", err
	}

	outputBuilder.WriteString(fixedVulnTableString.String())
	outputBuilder.WriteString("\n</details>\n")

	outputBuilder.WriteString("<details>\n")
	outputBuilder.WriteString("<summary>Existing vulnerabilities</summary>\n\n")

	if err := existingVulnTable.Render(); err != nil {
		return "", err
	}

	outputBuilder.WriteString(existingVulnTableString.String())
	outputBuilder.WriteString("\n</details>\n")

	outputBuilder.WriteString("\n---\n")

	return outputBuilder.String(), nil
}

func TrimDockerRegistryPrefixes(name string) string {
	name = strings.TrimPrefix(name, "docker.io/library/")
	name = strings.TrimPrefix(name, "docker.io/")
	name = strings.TrimPrefix(name, "registry.hub.docker.com/library/")
	name = strings.TrimPrefix(name, "registry.hub.docker.com/")
	name = strings.TrimPrefix(name, "index.docker.io/library/")
	name = strings.TrimPrefix(name, "index.docker.io/")

	return name
}

func sortRows(rows [][]string) [][]string {
	orderMap := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"none":     4,
		"unknown":  5,
	}

	sortFunc := func(i, j int, rowSlice [][]string) bool {
		s1 := strings.ToLower(rowSlice[i][1])
		s2 := strings.ToLower(rowSlice[j][1])
		rank1, ok1 := orderMap[s1]
		if !ok1 {
			rank1 = 100
		}
		rank2, ok2 := orderMap[s2]
		if !ok2 {
			rank2 = 100
		}
		return rank1 < rank2
	}

	sort.Slice(rows, func(i, j int) bool {
		return sortFunc(i, j, rows)
	})

	return rows
}

func setupTables(newVulnTableString *strings.Builder, fixedVulnTableString *strings.Builder, existingVulnTableString *strings.Builder) (newVulnTable *tablewriter.Table, fixedVulnTable *tablewriter.Table, existingVulnTable *tablewriter.Table) {
	renderConfig :=
		tablewriter.WithConfig(tablewriter.Config{Header: tw.CellConfig{
			Alignment:    tw.CellAlignment{Global: tw.AlignLeft},
			ColMaxWidths: tw.CellWidth{Global: 10000},
		}})

	newVulnTable = tablewriter.NewTable(newVulnTableString, tablewriter.WithRenderer(renderer.NewMarkdown()), renderConfig)
	fixedVulnTable = tablewriter.NewTable(fixedVulnTableString, tablewriter.WithRenderer(renderer.NewMarkdown()), renderConfig)
	existingVulnTable = tablewriter.NewTable(existingVulnTableString, tablewriter.WithRenderer(renderer.NewMarkdown()), renderConfig)

	tables := []*tablewriter.Table{newVulnTable, fixedVulnTable, existingVulnTable}

	for _, table := range tables {
		table.Header([]string{"ID", "Severity", "URL"})
	}

	return newVulnTable, fixedVulnTable, existingVulnTable
}

func generateTableRows(baseVulns []cyclonedx.Vulnerability, newVulns []cyclonedx.Vulnerability, vulnStatus map[string]int) (newVulnRows [][]string, fixedVulnRows [][]string, existingVulnRows [][]string, err error) {
	allVulns := []cyclonedx.Vulnerability{}
	allVulns = append(allVulns, baseVulns...)
	allVulns = append(allVulns, newVulns...)

	for vulnUID, status := range vulnStatus {
		vuln, err := getVulnByUID(vulnUID, allVulns)
		if err != nil {
			return newVulnRows, fixedVulnRows, existingVulnRows, err
		}
		var vulnUrl string
		parsedUrl, err := url.Parse(vuln.Source.URL)
		if err != nil || parsedUrl.Scheme == "" {
			vulnUrl = (*vuln.Advisories)[0].URL
		} else {
			vulnUrl = vuln.Source.URL
		}
		row := []string{
			vuln.ID,
			string((*vuln.Ratings)[0].Severity),
			vulnUrl,
		}
		switch status {
		case 0:
			newVulnRows = append(newVulnRows, row)
		case 1:
			existingVulnRows = append(existingVulnRows, row)
		case 2:
			fixedVulnRows = append(fixedVulnRows, row)
		}
	}
	return newVulnRows, fixedVulnRows, existingVulnRows, nil
}

func loadScanJson(filename string) (cyclonedx.BOM, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return cyclonedx.BOM{}, err
	}
	var scan cyclonedx.BOM
	if err := json.Unmarshal(data, &scan); err != nil {
		return cyclonedx.BOM{}, err
	}
	if scan.Vulnerabilities == nil {
		scan.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	return scan, nil
}

func getUniqueVulnId(vuln cyclonedx.Vulnerability) string {
	pkgPath := strings.Split((*vuln.Affects)[0].Ref, "@")[0]
	return fmt.Sprintf("%s|%s", vuln.ID, pkgPath)
}

func getVulnByUID(uid string, vulns []cyclonedx.Vulnerability) (cyclonedx.Vulnerability, error) {
	for _, vuln := range vulns {
		if getUniqueVulnId(vuln) == uid {
			return vuln, nil
		}
	}
	return cyclonedx.Vulnerability{}, fmt.Errorf("vulnerability not found: %s", uid)
}
