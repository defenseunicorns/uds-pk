// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// CLIVersion is set at build time via ldflags.
var CLIVersion = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of uds-pk",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(CLIVersion)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
