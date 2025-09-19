// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"fmt"
	"os"

	"github.com/defenseunicorns/uds-pk/src/compare"
	"github.com/spf13/cobra"
)

var (
	allowDifferentImages bool
	outputFormat         string
	failOnNewVulns       bool
)

var compareCmd = &cobra.Command{
	Use:   "compare-scans BASE_SCAN NEW_SCAN",
	Short: "Compare two grype scans using the cyclonedx-json output format",
	Long:
`Compare two grype scans using the cyclonedx-json output format.
Supports the following output formats:
  - markdown(default): Generates a markdown table of the comparison
  - simple: Generates a simple count of vulnerability statuses (new, existing, fixed)

If the scans are for different images, it will error unless --allow-different-images is set

Also supports failing if new vulnerabilities are found in the new scan compared to the base scan using the --fail-on-new-vulns flag.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		baseScan, newScan, err := compare.LoadScans(args[0], args[1])
		if err != nil {
			return err
		}

		baseScan.Metadata.Component.Name = compare.TrimDockerRegistryPrefixes(baseScan.Metadata.Component.Name)
		newScan.Metadata.Component.Name = compare.TrimDockerRegistryPrefixes(newScan.Metadata.Component.Name)

		if baseScan.Metadata.Component.Name != newScan.Metadata.Component.Name {
			if !allowDifferentImages {
				return fmt.Errorf("these scans are not for the same image: %s != %s", baseScan.Metadata.Component.Name, newScan.Metadata.Component.Name)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: these scans are not for the same image: %s != %s\n", baseScan.Metadata.Component.Name, newScan.Metadata.Component.Name)
			}
		}

		vulnStatus := compare.GenerateComparisonMap(baseScan, newScan)

		switch outputFormat {
		case "markdown":
			markdownTable, err := compare.GenerateComparisonMarkdown(baseScan, newScan, vulnStatus)
			if err != nil {
				return err
			}
			fmt.Println(markdownTable)
		case "simple":
			vulnCounts := compare.GenerateComparisonCounts(vulnStatus)
			fmt.Print(vulnCounts)
		default:
			return fmt.Errorf("unsupported output format: %s", outputFormat)
		}

		if failOnNewVulns {
			for _, status := range vulnStatus {
				if status == 0 {
					cmd.SilenceUsage = true
					return fmt.Errorf("new vulnerabilities found in the new scan compared to the base scan")
				}
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(compareCmd)

	compareCmd.Flags().BoolVarP(&allowDifferentImages, "allow-different-images", "d", false, "Allow comparing scans for different images")
	compareCmd.Flags().StringVarP(&outputFormat, "output", "o", "markdown", "Output format for the comparison (markdown, simple)")
	compareCmd.Flags().BoolVarP(&failOnNewVulns, "fail-on-new-vulns", "f", false, "Fail if new vulnerabilities are found in the new scan compared to the base scan")
}
