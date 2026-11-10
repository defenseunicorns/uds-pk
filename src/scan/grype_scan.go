// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package scan

import (
	"crypto/sha256"
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
	preferred := map[string]string{}
	identities := map[string]Identity{}
	var sources []string
	for _, image := range images {
		if !strings.HasPrefix(image, "registry:") {
			image = "registry:" + image
		}
		if _, exists := preferred[image]; exists {
			continue
		}
		identity, err := ImageIdentity(image)
		if err != nil {
			return nil, err
		}
		identities[image] = identity
		preferred[image] = sanitizeFilename(image)
		sources = append(sources, image)
	}
	names, err := planOutputNames(preferred, func(source string) string { return source })
	if err != nil {
		return nil, err
	}
	results := map[string]string{}
	for _, image := range sources {
		logger.Debug("Will scan image", slog.String("image", image))
		out, err := scanImage(image, outputDir, names[image], identities[image], logger, isVerbose, processRunner)
		if err != nil {
			return nil, err
		}
		results[image] = out
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

	// Plan the whole batch before scanning so distinct resources cannot overwrite results.
	preferred := make(map[string]string, len(sbomFiles))
	identities := make(map[string]Identity, len(sbomFiles))
	for _, file := range sbomFiles {
		identity, err := sbomIdentity(file)
		if err != nil {
			return nil, err
		}
		identities[file] = identity
		preferred[file] = sbomOutputName(file, identity, logger)
	}
	names, err := planOutputNames(preferred, filepath.Base)
	if err != nil {
		return nil, err
	}

	results := map[string]string{}
	for _, sbomFile := range sbomFiles {
		outJson, err := scanSBOM(sbomFile, outputDir, names[sbomFile], identities[sbomFile], logger, isVerbose, processRunner)
		if err != nil {
			return nil, err
		} else {
			results[sbomFile] = outJson
		}

	}

	return results, nil
}

// planOutputNames preserves familiar names when unique and uses the full source identity
// for collisions. Names are planned before any scanner can overwrite another result.
func planOutputNames(preferred map[string]string, stableID func(string) string) (map[string]string, error) {
	counts := map[string]int{}
	for _, name := range preferred {
		counts[name]++
	}
	names := make(map[string]string, len(preferred))
	planned := map[string]bool{}
	for source, name := range preferred {
		if counts[name] > 1 || len(name) > 200 {
			name = fmt.Sprintf("%.140s--%x", name, sha256.Sum256([]byte(stableID(source))))
		}
		if planned[name] {
			return nil, fmt.Errorf("multiple scans produce output %q", name)
		}
		planned[name] = true
		names[source] = name
	}
	return names, nil
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

func sbomOutputName(sbomFile string, identity Identity, logger *slog.Logger) string {
	var safeImageName string
	if identity.Reference != "" {
		safeImageName = sanitizeFilename(identity.Reference)
		if identity.Platform != "" {
			safeImageName += "--" + sanitizeFilename(strings.ReplaceAll(identity.Platform, "/", "-"))
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
	return safeImageName
}

func scanSBOM(sbomFile string, outputDir string, safeImageName string, identity Identity, logger *slog.Logger, isVerbose bool, processRunner utils.RunProcess) (string, error) {
	logger.Debug("Scanning SBOM", slog.String("file", sbomFile))

	// Set up the output path if needed
	if outputDir == "" {
		return "", errors.New("output directory not specified")
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
	out, err := runGrypeCommand(args, jsonOutputPath, logger, isVerbose, processRunner)
	if err != nil {
		return "", err
	}
	if err := recordIdentity(out, identity); err != nil {
		return "", err
	}
	return out, nil
}

func scanImage(image, outputDir, safeImageName string, identity Identity, logger *slog.Logger, isVerbose bool, processRunner utils.RunProcess) (string, error) {
	logger.Debug("Scanning SBOM", slog.String("file", image))

	// Set up the output path if needed
	if outputDir == "" {
		return "", errors.New("output directory not specified")
	}

	jsonFileName := safeImageName + ".json"
	jsonOutputPath := filepath.Join(outputDir, jsonFileName)
	logger.Debug("Saving JSON results to output directory", slog.String("fileName", jsonOutputPath))

	// Ensure the output directory exists and is writable
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	args := []string{"--add-cpes-if-none", "--output", "cyclonedx-json", "-v", "--file", jsonOutputPath, image}

	// Try to scan with retries for database issues
	out, err := runGrypeCommand(args, jsonOutputPath, logger, isVerbose, processRunner)
	if err != nil {
		return "", err
	}
	if err := recordIdentity(out, identity); err != nil {
		return "", err
	}
	return out, nil
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
