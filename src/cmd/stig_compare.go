// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/defenseunicorns/uds-pk/src/stig"
	"github.com/spf13/cobra"
)

// CompareResultsOptions holds flags for the compare-results subcommand.
type CompareResultsOptions struct {
	OutputPath string
}

func compareResultsCmd() *cobra.Command {
	options := &CompareResultsOptions{}
	cmd := &cobra.Command{
		Use:          "compare-results BASE_RESULTS NEW_RESULTS",
		Short:        "Compare two XCCDF TestResult documents for STIG regressions",
		Args:         compareResultsArgs,
		RunE:         options.run,
		SilenceUsage: true,
	}
	cmd.Flags().StringVar(&options.OutputPath, "output", "", "Write comparison evidence to this path")
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return newExitCodeError(2, err)
	})
	return cmd
}

func compareResultsArgs(_ *cobra.Command, args []string) error {
	if len(args) != 2 {
		return newExitCodeError(2, fmt.Errorf("accepts 2 arg(s), received %d", len(args)))
	}
	return nil
}

func (o *CompareResultsOptions) run(cmd *cobra.Command, args []string) error {
	baseResults, err := stig.LoadXCCDFResults(args[0])
	if err != nil {
		return newExitCodeError(2, err)
	}
	newResults, err := stig.LoadXCCDFResults(args[1])
	if err != nil {
		return newExitCodeError(2, err)
	}
	comparison, err := stig.CompareXCCDFResults(baseResults, newResults)
	if err != nil {
		return newExitCodeError(2, err)
	}
	report := stig.RenderXCCDFComparison(comparison)
	if o.OutputPath != "" {
		if err := validateCompareResultsOutputPath(o.OutputPath, args[0], args[1]); err != nil {
			return newExitCodeError(2, err)
		}
		if err := os.WriteFile(o.OutputPath, []byte(report), 0o644); err != nil {
			return newExitCodeError(2, fmt.Errorf("writing comparison evidence: %w", err))
		}
	}
	if _, err := fmt.Fprint(cmd.OutOrStdout(), report); err != nil {
		return newExitCodeError(2, fmt.Errorf("writing comparison report: %w", err))
	}
	if comparison.HasRegressions() {
		return newExitCodeError(1, fmt.Errorf("XCCDF regressions detected"))
	}

	return nil
}

func validateCompareResultsOutputPath(outputPath string, inputPaths ...string) error {
	outputInfo, err := os.Stat(outputPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("resolving output path %q: %w", outputPath, err)
	}
	for _, inputPath := range inputPaths {
		inputInfo, err := os.Stat(inputPath)
		if err != nil {
			return fmt.Errorf("resolving input path %q: %w", inputPath, err)
		}
		if os.SameFile(outputInfo, inputInfo) {
			return fmt.Errorf("output path %q conflicts with input path %q", outputPath, inputPath)
		}
	}
	return nil
}
