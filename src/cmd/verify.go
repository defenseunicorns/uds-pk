// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	badgeVerify "github.com/defenseunicorns/uds-pk/src/verify"
	"github.com/zarf-dev/zarf/src/pkg/message"

	"github.com/spf13/cobra"
)

var baseDir string

var verifyCommand = &cobra.Command{
	Use:     "verify-badge",
	Aliases: []string{"v"},
	Short:   "Run Made for UDS badge verification",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := badgeVerify.VerifyBadge(baseDir)
		if err != nil {
			cmd.SilenceUsage = true
			message.WarnErr(err, "Errors occurred while running badge verifications.")
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(verifyCommand)
	verifyCommand.Flags().StringVarP(&baseDir, "dir", "d", ".", "Path to the root directory of the package")
}
