// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/defenseunicorns/uds-pk/src/utils"

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
		cmd := checkCmd()
		cmd.SetArgs(args)
		return cmd.Execute()
	},
}

// deprecatedShowCmd is the deprecated location for the show command
var deprecatedShowCmd = &cobra.Command{
	Use:    "show flavor",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE: func(_ *cobra.Command, args []string) error {
		fmt.Println("'uds-pk show' has been move to 'uds-pk release show' use of check at the command root will be removed in v0.1.0")
		cmd := showCmd()
		cmd.SetArgs(args)
		return cmd.Execute()
	},
}

// deprecatedUpdateYamlCmd is the deprecated location for the update-yaml command
var deprecatedUpdateYamlCmd = &cobra.Command{
	Use:    "update-yaml flavor",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE: func(_ *cobra.Command, args []string) error {
		fmt.Println("'uds-pk update-yaml' has been move to 'uds-pk release update-yaml' use of check at the command root will be removed in v0.1.0")
		cmd := updateYamlCmd()
		cmd.SetArgs(args)
		return cmd.Execute()
	},
}

type contextKey string

const loggerKey contextKey = "logger"
const verboseKey contextKey = "verbose"

func initLogger(cmd *cobra.Command, _ []string) {
	verbose, err := cmd.Root().PersistentFlags().GetBool("verbose")
	if err != nil {
		verbose = false
	}
	ctx := InitLoggerContext(verbose, cmd.Context())
	cmd.SetContext(ctx)
}

func InitLoggerContext(verbose bool, ctx context.Context) context.Context {
	logger := CreateLogger(verbose)
	ctx = context.WithValue(ctx, loggerKey, logger)
	return context.WithValue(ctx, verboseKey, verbose)
}

func CreateLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(utils.PrettyLogHandler(os.Stderr, level))
}

func Logger(ctx *context.Context) *slog.Logger {
	if ctx == nil {
		return CreateLogger(false)
	}
	return (*ctx).Value(loggerKey).(*slog.Logger)
}

func Verbose(ctx *context.Context) bool {
	if ctx == nil {
		return false
	}
	return (*ctx).Value(verboseKey).(bool)
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
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable debug output")
	rootCmd.PersistentPreRun = initLogger
	rootCmd.AddCommand(deprecatedCheckCmd)
	rootCmd.AddCommand(deprecatedShowCmd)
	rootCmd.AddCommand(deprecatedUpdateYamlCmd)
	rootCmd.AddCommand(initCmd)
}
