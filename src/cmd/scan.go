/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var compareCmd = &cobra.Command{
	Use:   "compare base.json new.json",
	Short: "Compare two grype scans using the json output type",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		baseScan := loadScanJson(args[0])
		newScan := loadScanJson(args[1])

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
		fmt.Println("<details>")
		fmt.Printf("<summary>%s:%s</summary>\n\n", newScan.Metadata.Component.Name, newScan.Metadata.Component.Version)

		fmt.Printf("New vulnerabilities: %d\n", newCount)
		fmt.Printf("Fixed vulnerabilities: %d\n", fixedCount)
		fmt.Printf("Existing vulnerabilities: %d\n\n", existingCount)

		newVulnTable := tablewriter.NewWriter(os.Stdout)
		fixedVulnTable := tablewriter.NewWriter(os.Stdout)
		existingVulnTable := tablewriter.NewWriter(os.Stdout)

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
			vuln := getVulnByUID(vulnUID, allVulns)
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

		fmt.Println("<details>")
		fmt.Println("<summary>New vulnerabilities</summary>\n")
		newVulnTable.Render()
		fmt.Println("\n</details>")

		fmt.Println("<details>")
		fmt.Println("<summary>Fixed vulnerabilities</summary>\n")
		fixedVulnTable.Render()
		fmt.Println("\n</details>")

		fmt.Println("<details>")
		fmt.Println("<summary>Existing vulnerabilities</summary>\n")
		existingVulnTable.Render()
		fmt.Println("\n</details>")

		fmt.Println("\n</details>")
	},
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Collection of commands for interacting with grype scans",
}

func getVulnByUID(uid string, vulns []cyclonedx.Vulnerability) cyclonedx.Vulnerability {
	for _, vuln := range vulns {
		if getUniqueVulnId(vuln) == uid {
			return vuln
		}
	}
	os.Exit(1)
	return cyclonedx.Vulnerability{}
}

func getUniqueVulnId(vuln cyclonedx.Vulnerability) string {
	return fmt.Sprintf("%s|%s", vuln.ID, (*vuln.Affects)[0].Ref)
}

// func loadScanJson(filename string) models.Document {
// 	data, err := os.ReadFile(filename)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
// 		os.Exit(1)
// 	}
// 	var scan models.Document
// 	if err := json.Unmarshal(data, &scan); err != nil {
// 		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
// 		os.Exit(1)
// 	}
// 	return scan
// }

func loadScanJson(filename string) cyclonedx.BOM {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}
	var scan cyclonedx.BOM
	if err := json.Unmarshal(data, &scan); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}
	return scan
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.AddCommand(compareCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// scanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// scanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
