// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/stig"
	"github.com/spf13/cobra"
)

// GenerateChecklistOptions holds flags for the generate-checklist subcommand.
type GenerateChecklistOptions struct {
	ProfilePath string
	XCCDFPaths  []string
	OutputPaths []string
}

func generateChecklistCmd() *cobra.Command {
	options := &GenerateChecklistOptions{}
	cmd := &cobra.Command{
		Use:   "generate-checklist",
		Short: "Generate a STIG checklist (.cklb) from a STIG profile and XCCDF content",
		RunE:  options.run,
	}
	cmd.Flags().StringVar(&options.ProfilePath, "profile", "stig-profile.yaml", "Path to stig-profile.yaml")
	cmd.Flags().StringSliceVar(&options.XCCDFPaths, "xccdf", nil, "Comma-separated XCCDF XML paths in profile order (optional when the profile identifies supported DISA STIGs)")
	cmd.Flags().StringSliceVar(&options.OutputPaths, "output", nil, "Comma-separated output .cklb paths in profile order (default: <app_name>-<stig>-<revision>.cklb)")
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
	if err := profile.ValidateVersion(CLIVersion); err != nil {
		return fmt.Errorf("invalid profile schema version: %w", err)
	}
	if err := profile.ValidateSTIGs(); err != nil {
		return err
	}
	if err := profile.ValidateSchema(CLIVersion); err != nil {
		return fmt.Errorf("invalid profile schema: %w", err)
	}

	profiles := profile.SupportedSTIGs()
	if len(profiles) == 0 {
		return fmt.Errorf("no supported STIG found in profile")
	}
	if err := validateUniqueSTIGs(profiles); err != nil {
		return err
	}
	if err := validatePathCount("xccdf", o.XCCDFPaths, len(profiles)); err != nil {
		return err
	}
	if err := validatePathCount("output", o.OutputPaths, len(profiles)); err != nil {
		return err
	}
	outputPaths, err := resolveOutputPaths(profile.AppName, profiles, o.OutputPaths)
	if err != nil {
		return err
	}
	if err := validateOutputPathsDoNotOverwriteXCCDFs(outputPaths, o.XCCDFPaths); err != nil {
		return err
	}

	for i, stigProfile := range profiles {
		profile.ActivateSTIG(stigProfile)
		xccdfPath := pathAt(o.XCCDFPaths, i)
		outputPath := outputPaths[i]
		if err := generateChecklist(ctx, cmd, log, profile, xccdfPath, outputPath); err != nil {
			return fmt.Errorf("generating checklist for STIG %q: %w", stigProfile.ID, err)
		}
	}
	return nil
}

func validateUniqueSTIGs(profiles []*stig.STIGProfile) error {
	seen := map[string]struct{}{}
	for _, profile := range profiles {
		if _, exists := seen[profile.ID]; exists {
			return fmt.Errorf("profile contains duplicate STIG %q", profile.ID)
		}
		seen[profile.ID] = struct{}{}
	}
	return nil
}

func validatePathCount(flagName string, paths []string, stigCount int) error {
	if len(paths) != 0 && len(paths) != stigCount {
		return fmt.Errorf("--%s must contain one path per supported STIG: got %d paths for %d STIGs", flagName, len(paths), stigCount)
	}
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("--%s must not contain empty paths", flagName)
		}
	}
	return nil
}

func pathAt(paths []string, index int) string {
	if len(paths) == 0 {
		return ""
	}
	return paths[index]
}

func validateOutputPathsDoNotOverwriteXCCDFs(outputPaths, xccdfPaths []string) error {
	xccdfPathSet := make(map[string]string, len(xccdfPaths))
	for _, path := range xccdfPaths {
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolving XCCDF path %q: %w", path, err)
		}
		xccdfPathSet[absolutePath] = path
	}

	for _, path := range outputPaths {
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolving output path %q: %w", path, err)
		}
		if xccdfPath, exists := xccdfPathSet[absolutePath]; exists {
			return fmt.Errorf("output path %q conflicts with XCCDF input path %q", path, xccdfPath)
		}
	}
	return nil
}

func resolveOutputPaths(appName string, profiles []*stig.STIGProfile, explicitPaths []string) ([]string, error) {
	paths := explicitPaths
	if len(paths) == 0 {
		paths = make([]string, len(profiles))
		for i, profile := range profiles {
			definition, err := stig.LookupSTIGDefinition(profile.ID)
			if err != nil {
				return nil, fmt.Errorf("determining output path for STIG %q: %w", profile.ID, err)
			}
			paths[i] = stig.DefaultChecklistFilename(appName, definition)
		}
	}

	seen := map[string]struct{}{}
	for _, path := range paths {
		resolvedPath, err := resolveOutputPath(path)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[resolvedPath]; exists {
			return nil, fmt.Errorf("output paths must be unique: %q is used more than once", path)
		}
		seen[resolvedPath] = struct{}{}
	}
	return paths, nil
}

func resolveOutputPath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving output path %q: %w", path, err)
	}

	if resolvedPath, err := filepath.EvalSymlinks(absolutePath); err == nil {
		return resolvedPath, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolving output path symlinks for %q: %w", path, err)
	}

	absoluteDir := filepath.Dir(absolutePath)
	resolvedDir, err := filepath.EvalSymlinks(absoluteDir)
	if err == nil {
		return filepath.Join(resolvedDir, filepath.Base(absolutePath)), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolving output path directory symlinks for %q: %w", path, err)
	}

	return absolutePath, nil
}

func generateChecklist(ctx context.Context, cmd *cobra.Command, log *slog.Logger, profile *stig.Profile, explicitXCCDFPath, outputPath string) error {
	xccdfPath, cleanup, err := stig.ResolveXCCDFPath(ctx, profile, explicitXCCDFPath)
	if err != nil {
		return fmt.Errorf("resolving XCCDF: %w", err)
	}
	defer cleanup()

	log.Info("Parsing XCCDF", slog.String("path", xccdfPath), slog.String("stig", profile.SelectedSTIG.ID))
	parsedSTIG, err := stig.ParseXCCDF(xccdfPath, profile)
	if err != nil {
		return fmt.Errorf("failed to parse XCCDF: %w", err)
	}

	data, err := json.MarshalIndent(stig.BuildChecklist(profile, parsedSTIG), "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling JSON: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	counts := map[string]int{}
	for _, rule := range parsedSTIG.Rules {
		counts[rule.Status]++
	}
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(w, "Generated %s\n", outputPath)
	_, _ = fmt.Fprintf(w, "Total rules: %d\n", len(parsedSTIG.Rules))
	for _, status := range []string{"not_a_finding", "not_applicable", "not_reviewed", "open"} {
		if count, ok := counts[status]; ok {
			_, _ = fmt.Fprintf(w, "  %s: %d\n", status, count)
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
	stigCmd.AddCommand(compareResultsCmd())
	rootCmd.AddCommand(stigCmd)
}
