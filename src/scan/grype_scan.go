// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseunicorns/uds-pk/src/utils"
)

/*
Scanning logic is heavily inspired by https://github.com/defenseunicorns-navy/sonic-components-zarf-scan
*/

func Images(images []string, outputDir string, logger *slog.Logger, isVerbose bool, processRunner utils.RunProcess) (map[string]string, error) {
	results := map[string]string{}
	for _, image := range images {
		// adding registry: to make `grype` pull the image from the registry
		// this avoids issues with containerd snapshotting in Docker
		if !strings.HasPrefix(image, "registry:") {
			image = "registry:" + image
		}
		logger.Debug("Will scan image", slog.String("image", image))
		outJson, err := scanImage(image, outputDir, logger, isVerbose, processRunner)
		if err != nil {
			return nil, err
		} else {
			results[image] = outJson
		}
	}
	return results, nil
}

func SBOMs(sbomsDir, outputDir string, logger *slog.Logger, isVerbose bool, processRunner utils.RunProcess) (map[string]string, error) {
	// Find only JSON files in the sboms directory
	pattern := filepath.Join(sbomsDir, "*.json")
	sbomFiles, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("error finding SBOM JSON files: %w", err)
	}

	if len(sbomFiles) == 0 {
		return nil, errors.New("no SBOM files to scan")
	}

	logger.Debug("Found SBOM files to scan", slog.Int("count", len(sbomFiles)))

	results := map[string]string{}
	for _, sbomFile := range sbomFiles {
		outJson, err := scanSBOM(sbomFile, outputDir, logger, isVerbose, processRunner)
		if err != nil {
			return nil, err
		} else {
			results[sbomFile] = outJson
		}

	}

	return results, nil
}

func extractImageName(fullPath string) string {
	// Split by "/" and take the last part
	parts := strings.Split(fullPath, "/")
	imageName := parts[len(parts)-1]

	return imageName
}

// Replacer for common characters that are problematic in filenames
var replacer = strings.NewReplacer(
	"/", "_",
	":", "_",
	" ", "_",
	",", "_",
	"@", "_",
	"&", "_",
	"=", "_",
	"?", "_",
	"#", "_",
	"%", "_",
	"*", "_",
	"\"", "_",
	"'", "_",
	"`", "_",
	"<", "_",
	">", "_",
	"|", "_",
	"\\", "_",
	"!", "_",
)

func sanitizeFilename(name string) string {
	name = extractImageName(name)

	// Perform the replacements
	sanitized := replacer.Replace(name)

	// Ensure we don't have multiple consecutive underscores
	for strings.Contains(sanitized, "__") {
		sanitized = strings.ReplaceAll(sanitized, "__", "_")
	}

	// Trim underscores from start and end
	sanitized = strings.Trim(sanitized, "_")

	// If we somehow end up with an empty string, use a default name
	if sanitized == "" {
		sanitized = "unknown_file"
	}

	return sanitized
}

func scanSBOM(sbomFile string, outputDir string, logger *slog.Logger, isVerbose bool, processRunner utils.RunProcess) (string, error) {
	logger.Debug("Scanning SBOM", slog.String("file", sbomFile))

	// Set up the output path if needed
	if outputDir == "" {
		return "", errors.New("output directory not specified")
	}

	// Extract image reference from SBOM if possible
	var safeImageName string

	// Try to extract the image reference using JSON parsing
	if data, err := os.ReadFile(sbomFile); err == nil {
		var sbom struct {
			Source struct {
				Metadata struct {
					UserInput string `json:"userInput"`
				} `json:"metadata"`
			} `json:"source"`
		}

		if err := json.Unmarshal(data, &sbom); err == nil && sbom.Source.Metadata.UserInput != "" {
			imageRef := sbom.Source.Metadata.UserInput
			logger.Debug("Found image reference in SBOM", slog.String("imageRef", imageRef))
			safeImageName = sanitizeFilename(filepath.Base(imageRef))
		}
	}

	// If we couldn't extract the image ref, use the SBOM filename
	if safeImageName == "" {
		baseName := filepath.Base(sbomFile)
		fileExt := filepath.Ext(baseName)
		safeImageName = baseName[:len(baseName)-len(fileExt)]
		safeImageName = sanitizeFilename(safeImageName)
		logger.Debug("Using SBOM filename for output", slog.String("safeImageName", safeImageName))
	}
	jsonFileName := safeImageName + ".json"
	jsonOutputPath := filepath.Join(outputDir, jsonFileName)
	logger.Debug("Saving JSON results to output directory", slog.String("fileName", jsonOutputPath))

	// Ensure the output directory exists and is writable
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}
	file, err := os.Create(jsonOutputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file %s: %w", jsonOutputPath, err)
	}
	_ = file.Close()

	args := []string{"--add-cpes-if-none", "--output", "cyclonedx-json", "-v", "--file", jsonOutputPath, "sbom:" + sbomFile}

	// Try to scan with retries for database issues
	return runGrypeCommand(args, jsonOutputPath, logger, isVerbose, processRunner)
}

func scanImage(image, outputDir string, logger *slog.Logger, isVerbose bool, processRunner utils.RunProcess) (string, error) {
	logger.Debug("Scanning SBOM", slog.String("file", image))

	// Set up the output path if needed
	if outputDir == "" {
		return "", errors.New("output directory not specified")
	}

	// If we couldn't extract the image ref, use the SBOM filename
	safeImageName := sanitizeFilename(image)
	jsonFileName := safeImageName + ".json"
	jsonOutputPath := filepath.Join(outputDir, jsonFileName)
	logger.Debug("Saving JSON results to output directory", slog.String("fileName", jsonOutputPath))

	// Ensure the output directory exists and is writable
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	args := []string{"--add-cpes-if-none", "--output", "cyclonedx-json", "-v", "--file", jsonOutputPath, image}

	// Try to scan with retries for database issues
	return runGrypeCommand(args, jsonOutputPath, logger, isVerbose, processRunner)
}

func runGrypeCommand(args []string, jsonOutputPath string, logger *slog.Logger, isVerbose bool, processRunner utils.RunProcess) (string, error) {
	// Maximum retry attempts for handling database issues
	maxRetries := 3
	retryCount := 0
	for retryCount < maxRetries {
		// Create the command - this needs to be inside the loop because we can't reuse commands

		logger.Debug("Running grype command", slog.Any("args", args))
		cmd := processRunner("grype", args...)
		configureOutput(cmd, isVerbose)

		logger.Debug("Running scan", slog.Int("attempt", retryCount+1), slog.String("command", "grype "+strings.Join(args, " ")))

		err := cmd.Run()

		if err == nil {
			return jsonOutputPath, nil
		}
		logger.Debug("Error from grype command:", slog.Any("error", err))
		// Check if this is a database error
		checkCmd := processRunner("grype", "db", "status")
		configureOutput(checkCmd, isVerbose)
		output, _ := checkCmd.CombinedOutput()

		if strings.Contains(string(output), "failed to load vulnerability db") {
			logger.Info("Vulnerability database error detected. Running Grype DB update...",
				"attempt", retryCount+1, "maxRetries", maxRetries)

			// Update the database
			updateCmd := processRunner("grype", "db", "update")
			configureOutput(updateCmd, isVerbose)

			if updateErr := updateCmd.Run(); updateErr != nil {
				logger.Info("Failed to update Grype database", "error", updateErr)
			}

			retryCount++
			time.Sleep(5 * time.Second) // Wait before retrying
			continue
		}

		return "", fmt.Errorf("grype scan failed for %v", args)
	}
	return "", fmt.Errorf("grype scan failed for %v", args)
}

func configureOutput(cmd utils.CommandRunner, isVerbose bool) {
	if isVerbose {
		cmd.SetStdout(os.Stderr)
		cmd.SetStderr(os.Stderr)
	} else {
		cmd.SetStdout(io.Discard)
		cmd.SetStderr(io.Discard)
	}
}
