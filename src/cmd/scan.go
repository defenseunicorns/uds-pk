/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/spf13/cobra"
)

var compareCmd = &cobra.Command{
	Use:   "compare base.json new.json",
	Short: "Compare two grype scans using the json output type",
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("compare called")
		baseScan := loadScanJson(args[0])
		newScan := loadScanJson(args[1])

		baseMatches := make(map[string]bool)
		for _, match := range baseScan.Matches {
			baseMatches[match.Vulnerability.ID] = true
		}

		for _, match := range newScan.Matches {
			if !baseMatches[match.Vulnerability.ID] {
				fmt.Printf("New issue: %s in package %s\n", match.Vulnerability.ID, match.Artifact.Name)
			}
		}
	},
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Collection of commands for interacting with grype scans",
}

func loadScanJson(filename string) models.Document {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}
	var scan models.Document
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
