// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"archive/tar"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type IndexEntry struct {
	Digest   string   `json:"digest"`
	Platform Platform `json:"platform"`
}

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type ImageIndex struct {
	Manifests []IndexEntry `json:"manifests"`
}

type Layer struct {
	Digest      string            `json:"digest"`
	Annotations map[string]string `json:"annotations"`
}

type ImageManifest struct {
	Layers []Layer `json:"layers"`
}

func GetAuthToken() string {
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken != "" {
		return base64.StdEncoding.EncodeToString([]byte(githubToken))
	}
	gitlabToken := os.Getenv("GITLAB_RELEASE_TOKEN")
	return gitlabToken
}

// FetchSboms fetches the sboms from the given Zarf image reference
// it expects the image to have a single manifest of type `application/vnd.oci.image.index.v1+json`
// that contains a single manifest of type `application/vnd.oci.image.manifest.v1+json`
// in this manifest, it searches for sboms.tar.
// Contents of this file are extracted to the outputDir, and their names are returned
func FetchSboms(repoOwner, packageUrl, tag string, outputDir string, logger *slog.Logger) ([]string, error) {

	base := "https://ghcr.io/v2/" + repoOwner + "/" + packageUrl

	indexUrl := base + "/manifests/" + tag

	idx, err2 := FetchImageIndex(indexUrl, logger)
	if err2 != nil {
		return nil, err2
	}

	authToken := GetAuthToken()
	var indexDigest = ""
	for _, manifest := range idx.Manifests {
		// we expect only one index manifest
		indexDigest = manifest.Digest
		break // there should be only one sboms.tar manifest
	}

	manifestUrl := base + "/manifests/" + indexDigest
	manifestBody, err := getByteArray(manifestUrl, authToken, "application/vnd.oci.image.manifest.v1+json")
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest json: %w from: %s", err, manifestUrl)
	}

	var manifest ImageManifest
	var sbomsDigest string
	if err := json.Unmarshal(manifestBody, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest json: %w %s", err, string(manifestBody))
	} else {
		for _, layer := range manifest.Layers {
			if layer.Annotations["org.opencontainers.image.title"] == "sboms.tar" {
				logger.Debug("found sboms.tar layer", slog.String("digest", layer.Digest))
				sbomsDigest = layer.Digest
				break
			}
		}
	}

	sbomsUrl := base + "/blobs/" + sbomsDigest

	var extractedFiles []string

	if err := walkRemoteTarArchive(sbomsUrl, authToken, logger, func(header *tar.Header, entry io.Reader) error {
		logger.Debug("extracting sbom", slog.String("name", header.Name))
		if header.Typeflag == tar.TypeReg && strings.HasSuffix(header.Name, "json") {
			outPath := filepath.Join(outputDir, header.Name)
			outFile, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer func(outFile io.ReadCloser) {
				err := outFile.Close()
				if err != nil {
					logger.Warn("Failed to close output SBOM file", slog.Any("error", err))
				}
			}(outFile)
			_, err = io.Copy(outFile, entry)
			if err != nil {
				return fmt.Errorf("failed to copy sbom out of tar: %w", err)
			}
			extractedFiles = append(extractedFiles, outPath)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return extractedFiles, nil
}

func FetchImageIndex(indexUrl string, logger *slog.Logger) (ImageIndex, error) {
	authToken := GetAuthToken()

	indexBody, err := getByteArray(indexUrl, authToken, "application/vnd.oci.image.index.v1+json")
	if err != nil {
		return ImageIndex{}, fmt.Errorf("failed to get index json: '%w' from: %s", err, indexUrl)
	}

	logger.Debug("successfully fetched index json")
	var idx ImageIndex
	if err := json.Unmarshal(indexBody, &idx); err != nil {
		return ImageIndex{}, fmt.Errorf("failed to unmarshal index json: %w %s", err, string(indexBody))
	}
	return idx, nil
}

func getByteArray(url string, authToken string, contentType string) ([]byte, error) {
	response, err := get(url, authToken, contentType)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(response.Body)
	return body, err
}

func walkRemoteTarArchive(url string, githubToken string, log *slog.Logger, entryHandler func(hdr *tar.Header, entry io.Reader) error) error {
	response, err := get(url, githubToken, "application/octet-stream")
	if err != nil {
		return err
	}
	defer response.Body.Close() //nolint:errcheck
	tarReader := tar.NewReader(response.Body)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}
		if err := entryHandler(header, tarReader); err != nil {
			return err
		}
	}
	return nil
}

func get(url string, authToken string, contentType string) (*http.Response, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", contentType)
	if authToken != "" {
		request.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("unexpected status code: " + response.Status)
	}
	return response, nil
}
