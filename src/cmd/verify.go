// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	badgeVerify "github.com/defenseunicorns/uds-pk/src/verify"
	"github.com/zarf-dev/zarf/src/pkg/message"

	"github.com/spf13/cobra"
)

var baseDir string

// checkCmd represents the check command
var verifyCommand = &cobra.Command{
	Use:   "verify",
	Short: "Run Made for UDS badge verification",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := badgeVerify.VerifyBadge(baseDir)
		if err != nil {
			message.WarnErr(err, "Failed to run badge verification.")
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(verifyCommand)
	verifyCommand.PersistentFlags().StringVarP(&baseDir, "dir", "d", ".", "Path to the root directory of the package")
}
