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
	checklists := make([]*generatedChecklist, 0, len(profiles))
	revisions := make([]string, 0, len(profiles))
	for i, stigProfile := range profiles {
		profile.ActivateSTIG(stigProfile)
		xccdfPath := pathAt(o.XCCDFPaths, i)
		checklist, err := prepareChecklist(ctx, log, profile, xccdfPath)
		if err != nil {
			return fmt.Errorf("generating checklist for STIG %q: %w", stigProfile.ID, err)
		}
		checklists = append(checklists, checklist)
		revisions = append(revisions, checklist.revision)
	}

	outputPaths, err := resolveOutputPaths(profile.AppName, profiles, revisions, o.OutputPaths)
	if err != nil {
		return err
	}
	if err := validateOutputPathsDoNotOverwriteXCCDFs(outputPaths, o.XCCDFPaths); err != nil {
		return err
	}
	for i, checklist := range checklists {
		checklist.outputPath = outputPaths[i]
		checklist.destinationPath, err = resolveOutputPath(outputPaths[i])
		if err != nil {
			return err
		}
	}

	if err := writeChecklists(cmd, checklists); err != nil {
		return err
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
	existingXCCDFs := []existingPath{}
	for _, path := range xccdfPaths {
		resolved, err := resolveOutputPath(path)
		if err != nil {
			return fmt.Errorf("resolving XCCDF path %q: %w", path, err)
		}
		xccdfPathSet[resolved] = path

		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stating XCCDF path %q: %w", path, err)
		}
		existingXCCDFs = append(existingXCCDFs, existingPath{path: path, info: info})
	}

	for _, path := range outputPaths {
		resolved, err := resolveOutputPath(path)
		if err != nil {
			return err
		}
		if xccdfPath, exists := xccdfPathSet[resolved]; exists {
			return fmt.Errorf("output path %q conflicts with XCCDF input path %q", path, xccdfPath)
		}

		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stating output path %q: %w", path, err)
		}
		for _, xccdf := range existingXCCDFs {
			if os.SameFile(info, xccdf.info) {
				return fmt.Errorf("output path %q conflicts with XCCDF input path %q", path, xccdf.path)
			}
		}
	}
	return nil
}

type existingPath struct {
	path string
	info os.FileInfo
}

func resolveOutputPaths(appName string, profiles []*stig.STIGProfile, revisions, explicitPaths []string) ([]string, error) {
	paths := explicitPaths
	if len(paths) == 0 {
		paths = make([]string, len(profiles))
		for i, profile := range profiles {
			definition, err := stig.LookupSTIGDefinition(profile.ID)
			if err != nil {
				return nil, fmt.Errorf("determining output path for STIG %q: %w", profile.ID, err)
			}
			paths[i] = stig.DefaultChecklistFilename(appName, definition, revisions[i])
		}
	}

	seen := map[string]struct{}{}
	existingOutputs := []os.FileInfo{}
	for _, path := range paths {
		resolvedPath, err := resolveOutputPath(path)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[resolvedPath]; exists {
			return nil, fmt.Errorf("output paths must be unique: %q is used more than once", path)
		}
		seen[resolvedPath] = struct{}{}

		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stating output path %q: %w", path, err)
		}
		for _, existingInfo := range existingOutputs {
			if os.SameFile(info, existingInfo) {
				return nil, fmt.Errorf("output paths must be unique: %q is used more than once", path)
			}
		}
		existingOutputs = append(existingOutputs, info)
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

	info, err := os.Lstat(absolutePath)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(absolutePath)
		if err != nil {
			return "", fmt.Errorf("reading output path symlink %q: %w", path, err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(absolutePath), target)
		}
		return resolveOutputPath(target)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stating output path %q: %w", path, err)
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

type generatedChecklist struct {
	stigID          string
	revision        string
	outputPath      string
	destinationPath string
	data            []byte
	ruleCount       int
	statusCounts    map[string]int
}

func prepareChecklist(ctx context.Context, log *slog.Logger, profile *stig.Profile, explicitXCCDFPath string) (*generatedChecklist, error) {
	xccdfPath, cleanup, err := stig.ResolveXCCDFPath(ctx, profile, explicitXCCDFPath)
	if err != nil {
		return nil, fmt.Errorf("resolving XCCDF: %w", err)
	}
	defer cleanup()

	log.Info("Parsing XCCDF", slog.String("path", xccdfPath), slog.String("stig", profile.SelectedSTIG.ID))
	parsedSTIG, err := stig.ParseXCCDF(xccdfPath, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse XCCDF: %w", err)
	}

	data, err := json.MarshalIndent(stig.BuildChecklist(profile, parsedSTIG), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling JSON: %w", err)
	}
	counts := map[string]int{}
	for _, rule := range parsedSTIG.Rules {
		counts[rule.Status]++
	}
	return &generatedChecklist{
		stigID:       profile.SelectedSTIG.ID,
		revision:     parsedSTIG.Revision,
		data:         data,
		ruleCount:    len(parsedSTIG.Rules),
		statusCounts: counts,
	}, nil
}

type stagedChecklist struct {
	checklist    *generatedChecklist
	tempPath     string
	original     []byte
	originalMode os.FileMode
	existed      bool
	touched      bool
}

func writeChecklists(cmd *cobra.Command, checklists []*generatedChecklist) error {
	return writeChecklistsWithWriter(cmd, checklists, os.WriteFile)
}

func writeChecklistsWithWriter(cmd *cobra.Command, checklists []*generatedChecklist, writeFile func(string, []byte, os.FileMode) error) error {
	staged := make([]*stagedChecklist, 0, len(checklists))
	for _, checklist := range checklists {
		entry, err := stageChecklist(checklist)
		if err != nil {
			return cleanupAfterError(staged, fmt.Errorf("writing checklist for STIG %q: %w", checklist.stigID, err))
		}
		staged = append(staged, entry)
	}

	for _, entry := range staged {
		if entry.existed {
			entry.touched = true
			if err := writeFile(entry.checklist.destinationPath, entry.checklist.data, entry.originalMode); err != nil {
				return rollbackStagedChecklists(staged, writeFile, fmt.Errorf("writing checklist for STIG %q: %w", entry.checklist.stigID, err))
			}
		} else {
			if err := os.Rename(entry.tempPath, entry.checklist.destinationPath); err != nil {
				return rollbackStagedChecklists(staged, writeFile, fmt.Errorf("writing checklist for STIG %q: %w", entry.checklist.stigID, err))
			}
			entry.tempPath = ""
			entry.touched = true
		}
	}
	for _, entry := range staged {
		printChecklist(cmd, entry.checklist)
	}
	return nil
}

func stageChecklist(checklist *generatedChecklist) (*stagedChecklist, error) {
	return stageChecklistWithTempCreator(checklist, os.CreateTemp)
}

func stageChecklistWithTempCreator(checklist *generatedChecklist, createTemp func(string, string) (*os.File, error)) (*stagedChecklist, error) {
	mode := os.FileMode(0o644)
	entry := &stagedChecklist{checklist: checklist}
	info, err := os.Stat(checklist.destinationPath)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("output path %q is not a regular file", checklist.outputPath)
		}
		mode = info.Mode().Perm()
		entry.original, err = os.ReadFile(checklist.destinationPath)
		if err != nil {
			return nil, fmt.Errorf("reading existing output %q: %w", checklist.outputPath, err)
		}
		entry.originalMode = mode
		entry.existed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stating output path %q: %w", checklist.outputPath, err)
	}

	temp, err := createTemp(filepath.Dir(checklist.destinationPath), "."+filepath.Base(checklist.destinationPath)+"-*")
	if err != nil {
		if entry.existed && errors.Is(err, os.ErrPermission) {
			return entry, nil
		}
		return nil, fmt.Errorf("creating temporary output: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		if tempPath != "" {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := temp.Write(checklist.data); err != nil {
		_ = temp.Close()
		return nil, fmt.Errorf("writing temporary output: %w", err)
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return nil, fmt.Errorf("setting temporary output permissions: %w", err)
	}
	if err := temp.Close(); err != nil {
		return nil, fmt.Errorf("closing temporary output: %w", err)
	}
	if entry.existed {
		if err := os.Remove(tempPath); err != nil {
			return nil, fmt.Errorf("removing temporary output: %w", err)
		}
		tempPath = ""
		return entry, nil
	}

	tempPath = ""
	entry.tempPath = temp.Name()
	return entry, nil
}

func rollbackStagedChecklists(staged []*stagedChecklist, writeFile func(string, []byte, os.FileMode) error, originalErr error) error {
	var rollbackErr error
	cleanupErr := cleanupStagedTemps(staged)
	for _, entry := range staged {
		if entry.touched && !entry.existed {
			if err := os.Remove(entry.checklist.destinationPath); err != nil && !errors.Is(err, os.ErrNotExist) && rollbackErr == nil {
				rollbackErr = err
			}
		}
	}
	for _, entry := range staged {
		if !entry.touched || !entry.existed {
			continue
		}
		if err := writeFile(entry.checklist.destinationPath, entry.original, entry.originalMode); err != nil && rollbackErr == nil {
			rollbackErr = err
		}
	}
	if rollbackErr != nil && cleanupErr != nil {
		return fmt.Errorf("%w (restoring previous outputs: %v; cleaning staged outputs: %v)", originalErr, rollbackErr, cleanupErr)
	}
	if rollbackErr != nil {
		return fmt.Errorf("%w (restoring previous outputs: %v)", originalErr, rollbackErr)
	}
	if cleanupErr != nil {
		return fmt.Errorf("%w (cleaning staged outputs: %v)", originalErr, cleanupErr)
	}
	return originalErr
}

func cleanupAfterError(staged []*stagedChecklist, originalErr error) error {
	if cleanupErr := cleanupStagedTemps(staged); cleanupErr != nil {
		return fmt.Errorf("%w (cleaning staged outputs: %v)", originalErr, cleanupErr)
	}
	return originalErr
}

func cleanupStagedTemps(staged []*stagedChecklist) error {
	var cleanupErr error
	for _, entry := range staged {
		if entry.tempPath != "" {
			if err := os.Remove(entry.tempPath); err != nil && !errors.Is(err, os.ErrNotExist) && cleanupErr == nil {
				cleanupErr = err
			}
		}
	}
	return cleanupErr
}

func printChecklist(cmd *cobra.Command, checklist *generatedChecklist) {
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(w, "Generated %s\n", checklist.outputPath)
	_, _ = fmt.Fprintf(w, "Total rules: %d\n", checklist.ruleCount)
	for _, status := range []string{"not_a_finding", "not_applicable", "not_reviewed", "open"} {
		if count, ok := checklist.statusCounts[status]; ok {
			_, _ = fmt.Fprintf(w, "  %s: %d\n", status, count)
		}
	}
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
