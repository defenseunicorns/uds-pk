// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"fmt"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "uds-pk",
	Short: "UDS Package Kit is a tool for managing UDS packages",
	Long: `UDS Package Kit is a tool that facilitates the development, maintenance and release
	of UDS packages. It provides commands for automating releases verifying packages and
	generating configuration.`,
}

// deprecatedCheckCmd is the deprecated location for the check command
var deprecatedCheckCmd = &cobra.Command{
	Use:    "check flavor",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE: func(_ *cobra.Command, args []string) error {
		fmt.Println("'uds-pk check' has been moved to 'uds-pk release check' use of check at the command root will be removed in v0.1.0")
		return checkCmd.RunE(checkCmd, args)
	},
}

// deprecatedShowCmd is the deprecated location for the show command
var deprecatedShowCmd = &cobra.Command{
	Use:    "show flavor",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE: func(_ *cobra.Command, args []string) error {
		fmt.Println("'uds-pk show' has been move to 'uds-pk release show' use of check at the command root will be removed in v0.1.0")
		return showCmd.RunE(showCmd, args)
	},
}

// deprecatedUpdateYamlCmd is the deprecated location for the update-yaml command
var deprecatedUpdateYamlCmd = &cobra.Command{
	Use:    "update-yaml flavor",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE: func(_ *cobra.Command, args []string) error {
		fmt.Println("'uds-pk update-yaml' has been move to 'uds-pk release update-yaml' use of check at the command root will be removed in v0.1.0")
		return updateYamlCmd.RunE(updateYamlCmd, args)
	},
}

var verbose bool
var logger *slog.Logger

func setLogLevel(_ *cobra.Command, _ []string) {
	logger = getLogger(verbose)
}

func getLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(utils.PrettyLogHandler(os.Stderr, level))
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable debug output")
	rootCmd.PersistentPreRun = setLogLevel
	rootCmd.AddCommand(deprecatedCheckCmd)
	rootCmd.AddCommand(deprecatedShowCmd)
	rootCmd.AddCommand(deprecatedUpdateYamlCmd)
}
