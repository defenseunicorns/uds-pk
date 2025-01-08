// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var chartPath string
var groupName string
var packageDir string

// checkCmd represents the check command
var verifyCommand = &cobra.Command{
	Use:   "verify",
	Short: "Run Made for UDS badge verification",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Verify command called.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCommand)
}
