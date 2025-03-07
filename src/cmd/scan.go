/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/defenseunicorns/uds-pk/src/compare"
	"github.com/spf13/cobra"
)

var compareCmd = &cobra.Command{
	Use:   "compare-scans BASE_SCAN NEW_SCAN",
	Short: "Compare two grype scans using the cyclonedx-json output format",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		baseScan, newScan, err := compare.LoadScans(args[0], args[1])
		if err != nil {
			return err
		}

		if baseScan.Metadata.Component.Name != newScan.Metadata.Component.Name {
			return fmt.Errorf("These scans are not for the same image: %s != %s", baseScan.Metadata.Component.Name, newScan.Metadata.Component.Name)
		}

		vulnStatus := compare.GenerateComparisonMap(baseScan, newScan)

		markdownTable, err := compare.GenerateComparisonMarkdown(baseScan, newScan, vulnStatus)
		if err != nil {
			return err
		}

		fmt.Println(markdownTable)
		return nil
	},
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

func init() {
	rootCmd.AddCommand(compareCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// scanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// scanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
