// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/defenseunicorns/uds-pk/src/changelog"
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
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
	directory, err := filepath.Abs(options.releaseDir)
	if err != nil {
		return fmt.Errorf("resolve release directory: %w", err)
	}
	configPath := filepath.Join(directory, "releaser.yaml")
	var config types.ReleaseConfig
	if err := utils.LoadYaml(configPath, &config); err != nil {
		return fmt.Errorf("load release configuration %q: %w", configPath, err)
	}
	if err := config.Validate(); err != nil {
		return fmt.Errorf("validate release configuration %q: %w", configPath, err)
	}
	target, err := changelog.ResolveTarget(config, selection)
	if err != nil {
		return err
	}
	history, err := changelog.ReadHistory(cmd.Context(), directory, changelog.RevisionRange{From: options.from, To: options.to, Initial: options.initial})
	if err != nil {
		return err
	}
	commits, err := changelog.FilterCommits(cmd.Context(), history, directory, target, options.includePaths)
	if err != nil {
		return err
	}
	release := changelog.Release{Target: target, To: history.To.Hash.String(), RevisionDate: history.To.Committer.When, Sections: changelog.GroupCommits(commits)}
	if history.From != nil {
		release.From = history.From.Hash.String()
	}
	notes := changelog.RenderNotes(release, history.Origin)
	var artifacts []changelog.Artifact
	if options.output != "" {
		artifacts = append(artifacts, changelog.Artifact{Path: notesPath(directory, options.output), Content: notes})
	}
	if options.changelog != "" {
		path := notesPath(directory, options.changelog)
		existing, err := changelog.ReadArtifact(path)
		if err != nil {
			return fmt.Errorf("read changelog %q: %w", path, err)
		}
		updated, err := changelog.UpdateChangelog(existing, release, history.Origin)
		if err != nil {
			return fmt.Errorf("update changelog %q: %w", path, err)
		}
		artifacts = append(artifacts, changelog.Artifact{Path: path, Content: updated})
	}
	if err := cmd.Context().Err(); err != nil {
		return err
	}
	if err := changelog.WriteArtifacts(artifacts...); err != nil {
		return err
	}
	if options.output == "" {
		if _, err := cmd.OutOrStdout().Write(notes); err != nil {
			return fmt.Errorf("write release notes to stdout: %w", err)
		}
	}
	return nil
}

func notesPath(directory, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(directory, path)
}
