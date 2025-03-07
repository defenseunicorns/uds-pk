package compare

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/olekukonko/tablewriter"
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

	_, err := outputBuilder.WriteString(
		fmt.Sprintf(
			"### %s:%s -> %s:%s\n\n",
			baseScan.Metadata.Component.Name,
			baseScan.Metadata.Component.Version,
			newScan.Metadata.Component.Name,
			newScan.Metadata.Component.Version,
		),
	)
	if err != nil {
		return "", err
	}

	_, err = outputBuilder.WriteString(fmt.Sprintf("New vulnerabilities: %d\n", newCount))
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString(fmt.Sprintf("Fixed vulnerabilities: %d\n", fixedCount))
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString(fmt.Sprintf("Existing vulnerabilities: %d\n\n", existingCount))
	if err != nil {
		return "", err
	}

	newVulnTableString := &strings.Builder{}
	fixedVulnTableString := &strings.Builder{}
	existingVulnTableString := &strings.Builder{}

	newVulnTable := tablewriter.NewWriter(newVulnTableString)
	fixedVulnTable := tablewriter.NewWriter(fixedVulnTableString)
	existingVulnTable := tablewriter.NewWriter(existingVulnTableString)

	newVulnTable.SetHeader([]string{"ID", "Severity", "URL"})
	fixedVulnTable.SetHeader([]string{"ID", "Severity", "URL"})
	existingVulnTable.SetHeader([]string{"ID", "Severity", "URL"})

	newVulnTable.SetCenterSeparator("|")
	fixedVulnTable.SetCenterSeparator("|")
	existingVulnTable.SetCenterSeparator("|")

	newVulnTable.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	fixedVulnTable.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	existingVulnTable.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})

	allVulns := []cyclonedx.Vulnerability{}
	allVulns = append(allVulns, *baseScan.Vulnerabilities...)
	allVulns = append(allVulns, *newScan.Vulnerabilities...)

	newVulnRows := [][]string{}
	fixedVulnRows := [][]string{}
	existingVulnRows := [][]string{}

	for vulnUID, status := range vulnStatus {
		vuln, err := getVulnByUID(vulnUID, allVulns)
		if err != nil {
			return "", err
		}
		row := []string{
			vuln.ID,
			string((*vuln.Ratings)[0].Severity),
			vuln.Source.URL,
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

	sort.Slice(newVulnRows, func(i, j int) bool {
		return sortFunc(i, j, newVulnRows)
	})
	sort.Slice(fixedVulnRows, func(i, j int) bool {
		return sortFunc(i, j, fixedVulnRows)
	})
	sort.Slice(existingVulnRows, func(i, j int) bool {
		return sortFunc(i, j, existingVulnRows)
	})

	newVulnTable.AppendBulk(newVulnRows)
	fixedVulnTable.AppendBulk(fixedVulnRows)
	existingVulnTable.AppendBulk(existingVulnRows)

	_, err = outputBuilder.WriteString("<details>\n")
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString("<summary>New vulnerabilities</summary>\n\n")
	if err != nil {
		return "", err
	}
	newVulnTable.Render()
	_, err = outputBuilder.WriteString(newVulnTableString.String())
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString("\n</details>\n")
	if err != nil {
		return "", err
	}

	_, err = outputBuilder.WriteString("<details>\n")
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString("<summary>Fixed vulnerabilities</summary>\n\n")
	if err != nil {
		return "", err
	}
	fixedVulnTable.Render()
	_, err = outputBuilder.WriteString(fixedVulnTableString.String())
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString("\n</details>\n")
	if err != nil {
		return "", err
	}

	_, err = outputBuilder.WriteString("<details>\n")
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString("<summary>Existing vulnerabilities</summary>\n\n")
	if err != nil {
		return "", err
	}
	existingVulnTable.Render()
	_, err = outputBuilder.WriteString(existingVulnTableString.String())
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString("\n</details>\n")
	if err != nil {
		return "", err
	}
	_, err = outputBuilder.WriteString("\n---")
	if err != nil {
		return "", err
	}

	return outputBuilder.String(), nil
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
	return scan, nil
}

func getUniqueVulnId(vuln cyclonedx.Vulnerability) string {
	return fmt.Sprintf("%s|%s", vuln.ID, (*vuln.Affects)[0].Ref)
}

func getVulnByUID(uid string, vulns []cyclonedx.Vulnerability) (cyclonedx.Vulnerability, error) {
	for _, vuln := range vulns {
		if getUniqueVulnId(vuln) == uid {
			return vuln, nil
		}
	}
	return cyclonedx.Vulnerability{}, fmt.Errorf("Vulnerability not found: %s", uid)
}
