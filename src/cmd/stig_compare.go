// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	if o.OutputPath != "" {
		if err := validateCompareResultsOutputPath(o.OutputPath, args[0], args[1]); err != nil {
			return newExitCodeError(2, err)
		}
	}
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
	destination := cmd.OutOrStdout()
	var closeOutput func() error
	if o.OutputPath != "" {
		outputWriter, closeWriter, err := openCompareResultsOutputWriter(o.OutputPath, args, cmd.OutOrStdout(), cmd.ErrOrStderr())
		if err != nil {
			return newExitCodeError(2, err)
		}
		closeOutput = closeWriter
		destination = outputWriter
	}
	if _, err := fmt.Fprint(destination, report); err != nil {
		if closeOutput != nil {
			_ = closeOutput()
		}
		return newExitCodeError(2, fmt.Errorf("writing comparison report: %w", err))
	}
	if closeOutput != nil {
		if err := closeOutput(); err != nil {
			return newExitCodeError(2, fmt.Errorf("closing comparison evidence: %w", err))
		}
	}
	if comparison.HasRegressions() {
		return newExitCodeError(1, fmt.Errorf("XCCDF regressions detected"))
	}

	return nil
}

func validateCompareResultsOutputPath(outputPath string, inputPaths ...string) error {
	resolvedOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolving output path %q: %w", outputPath, err)
	}
	outputInfo, err := os.Stat(outputPath)
	outputExists := err == nil
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			outputExists = false
		} else {
			return fmt.Errorf("resolving output path %q: %w", outputPath, err)
		}
	}
	for _, inputPath := range inputPaths {
		resolvedInputPath, err := filepath.Abs(inputPath)
		if err != nil {
			return fmt.Errorf("resolving input path %q: %w", inputPath, err)
		}
		if resolvedOutputPath == resolvedInputPath {
			return fmt.Errorf("output path %q conflicts with input path %q", outputPath, inputPath)
		}
		if !outputExists {
			continue
		}
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

func openCompareResultsOutputWriter(outputPath string, inputPaths []string, stdout, stderr io.Writer) (io.Writer, func() error, error) {
	// Open without O_TRUNC so the inode selected by this open can be checked
	// against the inputs before modifying it.
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("writing comparison evidence: %w", err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("writing comparison evidence: %w", err)
	}
	for _, inputPath := range inputPaths {
		inputInfo, err := os.Stat(inputPath)
		if err != nil {
			_ = file.Close()
			return nil, nil, fmt.Errorf("resolving input path %q: %w", inputPath, err)
		}
		if os.SameFile(fileInfo, inputInfo) {
			_ = file.Close()
			return nil, nil, fmt.Errorf("output path %q conflicts with input path %q", outputPath, inputPath)
		}
	}
	if err := file.Truncate(0); err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("writing comparison evidence: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("writing comparison evidence: %w", err)
	}
	if writerMatchesFile(stdout, fileInfo) || writerMatchesFile(stderr, fileInfo) {
		return file, file.Close, nil
	}
	return io.MultiWriter(stdout, file), file.Close, nil
}

func writerMatchesFile(writer io.Writer, fileInfo os.FileInfo) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	writerInfo, err := file.Stat()
	if err != nil {
		return false
	}
	return os.SameFile(fileInfo, writerInfo)
}
