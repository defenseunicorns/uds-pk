// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/defenseunicorns/uds-pk/src/stig"
	"github.com/spf13/cobra"
)

// GenerateChecklistOptions holds flags for the generate-checklist subcommand.
type GenerateChecklistOptions struct {
	ProfilePath string
	XCCDFPath   string
	OutputPath  string
}

func generateChecklistCmd() *cobra.Command {
	options := &GenerateChecklistOptions{}
	cmd := &cobra.Command{
		Use:   "generate-checklist",
		Short: "Generate a STIG checklist (.cklb) from a STIG profile and XCCDF content",
		RunE:  options.run,
	}
	cmd.Flags().StringVar(&options.ProfilePath, "profile", "stig-profile.yaml", "Path to stig-profile.yaml")
	cmd.Flags().StringVar(&options.XCCDFPath, "xccdf", "", "Path to XCCDF XML file (optional when the profile identifies a supported DISA STIG)")
	cmd.Flags().StringVar(&options.OutputPath, "output", "", "Output .cklb file path (default: <app_name>-<stig>-<revision>.cklb)")
	return cmd
}

func (o *GenerateChecklistOptions) run(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	log := Logger(&ctx)

	log.Info("Loading profile", slog.String("path", o.ProfilePath))
	profile, err := stig.LoadProfile(o.ProfilePath)
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	outputPath := o.OutputPath
	if outputPath == "" {
		if profile.SelectedSTIG == nil {
			return fmt.Errorf("failed to determine output path: no supported STIG found in profile")
		}
		definition, err := stig.LookupSTIGDefinition(profile.SelectedSTIG.ID)
		if err != nil {
			return fmt.Errorf("failed to determine output path: %w", err)
		}
		outputPath = stig.DefaultChecklistFilename(profile.AppName, definition)
	}

	xccdfPath, cleanup, err := stig.ResolveXCCDFPath(ctx, profile, o.XCCDFPath)
	if err != nil {
		return fmt.Errorf("failed to resolve XCCDF: %w", err)
	}
	defer cleanup()

	log.Info("Parsing XCCDF", slog.String("path", xccdfPath))
	s, err := stig.ParseXCCDF(xccdfPath, profile)
	if err != nil {
		return fmt.Errorf("failed to parse XCCDF: %w", err)
	}

	checklist := stig.BuildChecklist(profile, s)

	data, err := json.MarshalIndent(checklist, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Print summary
	counts := map[string]int{}
	for _, r := range s.Rules {
		counts[r.Status]++
	}
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(w, "Generated %s\n", outputPath)
	_, _ = fmt.Fprintf(w, "Total rules: %d\n", len(s.Rules))
	for _, status := range []string{"not_a_finding", "not_applicable", "not_reviewed", "open"} {
		if c, ok := counts[status]; ok {
			_, _ = fmt.Fprintf(w, "  %s: %d\n", status, c)
		}
	}
	return nil
}

func init() {
	stigCmd := &cobra.Command{
		Use:   "stig",
		Short: "STIG checklist operations",
	}
	stigCmd.AddCommand(generateChecklistCmd())
	rootCmd.AddCommand(stigCmd)
}
