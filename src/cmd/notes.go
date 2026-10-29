// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"fmt"

	"github.com/defenseunicorns/uds-pk/src/changelog"
	"github.com/spf13/cobra"
)

type notesOptions struct {
	releaseDir   string
	packageName  string
	from         string
	to           string
	initial      bool
	output       string
	changelog    string
	includePaths []string
}

func notesCmd() *cobra.Command {
	options := &notesOptions{}
	cmd := &cobra.Command{
		Use:          "notes [flavor]",
		Short:        "Generate Markdown release notes and optionally update a changelog",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			selection := changelog.Selection{Package: options.packageName}
			if len(args) > 0 {
				selection.Flavor = args[0]
			}
			return options.run(cmd, selection)
		},
	}
	addPackageFlag(&options.packageName, cmd)
	addNotesFlags(cmd, options)
	return cmd
}

func bundleNotesCmd() *cobra.Command {
	options := &notesOptions{}
	cmd := &cobra.Command{
		Use:          "notes BUNDLE_NAME",
		Short:        "Generate Markdown release notes for a configured bundle",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return options.run(cmd, changelog.Selection{Bundle: args[0]})
		},
	}
	addNotesFlags(cmd, options)
	return cmd
}

func addNotesFlags(cmd *cobra.Command, options *notesOptions) {
	addReleaseDirFlag(&options.releaseDir, cmd)
	cmd.Flags().StringVar(&options.from, "from", "", "Baseline Git revision to exclude; required unless --initial is set")
	cmd.Flags().StringVar(&options.to, "to", "HEAD", "Last Git revision to include")
	cmd.Flags().BoolVar(&options.initial, "initial", false, "Generate a first release from all reachable history")
	cmd.Flags().StringVar(&options.output, "output", "", "Write release notes to this file instead of stdout; relative to --dir")
	cmd.Flags().StringVar(&options.changelog, "changelog", "", "Also update this changelog file; relative to --dir")
	cmd.Flags().StringArrayVar(&options.includePaths, "include-path", nil, "Include an additional shared file or directory relative to --dir; repeatable")
	cmd.MarkFlagsMutuallyExclusive("from", "initial")
	cmd.MarkFlagsOneRequired("from", "initial")
}

func (options *notesOptions) run(cmd *cobra.Command, selection changelog.Selection) error {
	for _, name := range []string{"output", "changelog"} {
		if cmd.Flags().Changed(name) {
			value, err := cmd.Flags().GetString(name)
			if err != nil {
				return err
			}
			if value == "" {
				return fmt.Errorf("--%s requires a non-empty file path", name)
			}
		}
	}
	generated, err := changelog.Generate(cmd.Context(), changelog.GenerateOptions{
		Directory: options.releaseDir, Selection: selection,
		Revisions:    changelog.RevisionRange{From: options.from, To: options.to, Initial: options.initial},
		IncludePaths: options.includePaths, Output: options.output, Changelog: options.changelog,
	})
	if err != nil {
		return err
	}
	if err := changelog.WriteArtifacts(generated.Artifacts...); err != nil {
		return err
	}
	if options.output == "" {
		if _, err := cmd.OutOrStdout().Write(generated.Notes); err != nil {
			return fmt.Errorf("write release notes to stdout: %w", err)
		}
	}
	return nil
}
