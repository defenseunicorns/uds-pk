// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"fmt"
	"os"

	"github.com/defenseunicorns/uds-pk/src/compare"
	"github.com/spf13/cobra"
)

var allowDifferentImages bool

var compareCmd = &cobra.Command{
	Use:   "compare-scans BASE_SCAN NEW_SCAN",
	Short: "Compare two grype scans using the cyclonedx-json output format",
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

		markdownTable, err := compare.GenerateComparisonMarkdown(baseScan, newScan, vulnStatus)
		if err != nil {
			return err
		}

		fmt.Println(markdownTable)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(compareCmd)

	compareCmd.Flags().BoolVarP(&allowDifferentImages, "allow-different-images", "d", false, "Allow comparing scans for different images")
}
