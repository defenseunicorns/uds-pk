// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"os"

	helmSchema "github.com/defenseunicorns/uds-pk/src/schema"
	"github.com/spf13/cobra"
	"github.com/zarf-dev/zarf/src/pkg/message"
)

func schema() *cobra.Command {
	var schemaCmd = &cobra.Command{
		Use:     "schema",
		Aliases: []string{"s"},
		Short:   "Generate and check JSON schemas for values.yaml files.",
	}

	return schemaCmd

}

func generateSchemas() *cobra.Command {
	var baseDir string

	generateSchemasCmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"g"},
		Short:   "Generate JSON schemas for all values.yaml files in a base directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := helmSchema.GenerateSchemas(baseDir); err != nil {
				message.WarnErr(err, "Failed to generate schemas")
			}
			return nil
		},
	}

	generateSchemasCmd.Flags().StringVarP(&baseDir, "base-dir", "b", "./charts", "Base directory to search for values.yaml files")
	return generateSchemasCmd
}

func checkSchemas() *cobra.Command {
	var baseDir string

	checkSchemasCmd := &cobra.Command{
		Use:     "validate",
		Aliases: []string{"v"},
		Short:   "Check if JSON schemas are up-to-date for all values.yaml files in a base directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := helmSchema.ValidateSchemas(baseDir); err != nil { //TODO(ewyles) -- Renamed this to ValidateSchemas to match the cli verb name
				message.WarnErrf(err, "Failed to check schemas for %s: \n%s", baseDir, err.Error())
				rootCmd.SilenceUsage = true
				os.Exit(1)
			}
			return nil
		},
	}

	checkSchemasCmd.Flags().StringVarP(&baseDir, "base-dir", "b", "./charts", "Base directory to search for values.yaml files")
	return checkSchemasCmd
}

func init() {
	schemaCmd := schema()

	schemaCmd.AddCommand(generateSchemas())
	schemaCmd.AddCommand(checkSchemas())
	rootCmd.AddCommand(schemaCmd)
}
