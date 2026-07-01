// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var xccdfHTTPClient = http.DefaultClient

func ResolveXCCDFPath(ctx context.Context, profile *Profile, explicitPath string) (string, func(), error) {
	if explicitPath != "" {
		return explicitPath, func() {}, nil
	}

	definition, err := definitionForProfile(profile)
	if err != nil {
		return "", func() {}, fmt.Errorf("no supported STIG found in profile and --xccdf was not provided")
	}
	if definition.ZipURL == "" || definition.XCCDFName == "" {
		return "", func() {}, fmt.Errorf("automatic XCCDF retrieval is not supported for STIG %q", definition.ID)
	}

	return downloadAndExtractXCCDF(ctx, definition.ZipURL, definition.XCCDFName)
}

func downloadAndExtractXCCDF(ctx context.Context, url, targetName string) (string, func(), error) {
	tempDir, err := os.MkdirTemp("", "uds-pk-stig-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating temp dir: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	zipPath := filepath.Join(tempDir, "source.zip")
	if err := downloadFile(ctx, url, zipPath); err != nil {
		cleanup()
		return "", func() {}, err
	}

	xccdfPath, err := extractXCCDF(zipPath, tempDir, targetName)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}

	return xccdfPath, cleanup, nil
}

func downloadFile(ctx context.Context, url, destPath string) (err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", url, err)
	}

	resp, err := xccdfHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer func() {
		closeErr := resp.Body.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("closing response body for %s: %w", url, closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: unexpected status %s", url, resp.Status)
	}

	file, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", destPath, err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("closing %s: %w", destPath, closeErr)
		}
	}()

	if _, err := io.Copy(file, resp.Body); err != nil {
		return fmt.Errorf("writing %s: %w", destPath, err)
	}

	return nil
}

func extractXCCDF(zipPath, destDir, targetName string) (_ string, err error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("opening zip %s: %w", zipPath, err)
	}
	defer func() {
		closeErr := reader.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("closing zip %s: %w", zipPath, closeErr)
		}
	}()

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if filepath.Base(file.Name) != targetName && !strings.HasSuffix(file.Name, "/"+targetName) {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			return "", fmt.Errorf("opening %s from zip: %w", file.Name, err)
		}

		outPath := filepath.Join(destDir, targetName)
		outFile, err := os.Create(outPath)
		if err != nil {
			if closeErr := rc.Close(); closeErr != nil {
				return "", fmt.Errorf("closing %s from zip: %w", file.Name, closeErr)
			}
			return "", fmt.Errorf("creating %s: %w", outPath, err)
		}

		_, copyErr := io.Copy(outFile, rc)
		closeErr := outFile.Close()
		rcErr := rc.Close()
		if copyErr != nil {
			return "", fmt.Errorf("extracting %s: %w", file.Name, copyErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("closing %s: %w", outPath, closeErr)
		}
		if rcErr != nil {
			return "", fmt.Errorf("closing %s from zip: %w", file.Name, rcErr)
		}

		return outPath, nil
	}

	return "", fmt.Errorf("did not find %s in %s", targetName, zipPath)
}
