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
	Digest string `json:"digest"`
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

func GetGithubToken() string {
	return os.Getenv("GITHUB_TOKEN")
}

// FetchSboms fetches the sboms from the given Zarf image reference
// it expects the image to have a single manifest of type `application/vnd.oci.image.index.v1+json`
// that contains a single manifest of type `application/vnd.oci.image.manifest.v1+json`
// in this manifest, it searches for sboms.tar.
// Contents of this file are extracted to the outputDir, and their names are returned
func FetchSboms(url string, outputDir string, logger *slog.Logger) ([]string, error) {
	githubToken := GetGithubToken()

	/*
		corresponds to:
			curl -H "Accept: application/vnd.oci.image.index.v1+json" \
			     -H "Authorization: Bearer $token" \
			     https://ghcr.io/v2/defenseunicorns/packages/uds/eck-elasticsearch/manifests/0.13.0-uds.5-registry1
	*/
	base, tag, err := splitImageUrl(url)
	if err != nil {
		return nil, err
	}
	indexUrl := base + "/manifests/" + tag
	indexBody, err := getByteArray(indexUrl, githubToken, "application/vnd.oci.image.index.v1+json")
	if err != nil {
		return nil, fmt.Errorf("failed to get index json: %w from: %s", err, indexUrl)
	}

	logger.Debug("successfully fetched index json")
	var idx ImageIndex
	if err := json.Unmarshal(indexBody, &idx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index json: %w %s", err, string(indexBody))
	}

	var indexDigest = ""
	for _, manifest := range idx.Manifests {
		// we expect only one index manifest
		indexDigest = manifest.Digest
		break // there should be only one sboms.tar manifest
	}

	manifestUrl := base + "/manifests/" + indexDigest
	manifestBody, err := getByteArray(manifestUrl, githubToken, "application/vnd.oci.image.manifest.v1+json")
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

	if err := walkRemoteTarArchive(sbomsUrl, githubToken, func(header *tar.Header, entry io.Reader) error {
		logger.Debug("extracting sbom", slog.String("name", header.Name))
		if header.Typeflag == tar.TypeReg && strings.HasSuffix(header.Name, "json") {
			outPath := filepath.Join(outputDir, header.Name)
			outFile, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer outFile.Close()
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

// splitImageUrl splits the image reference into base url and tag
// it also replaces oci:// with https://
func splitImageUrl(src string) (string, string, error) {
	idx := strings.LastIndex(src, ":")
	if idx == -1 {
		return "", "", errors.New("invalid image reference")
	}
	base := src[:idx]
	tag := src[idx+1:]
	if strings.HasPrefix(base, "oci://ghcr.io/") {
		base = "https://ghcr.io/v2/" + base[14:]
	}
	return base, tag, nil
}

func getByteArray(url string, githubToken string, contentType string) ([]byte, error) {
	response, err := get(url, githubToken, contentType)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)
	body, err := io.ReadAll(response.Body)
	return body, err
}

func walkRemoteTarArchive(url string, githubToken string, entryHandler func(hdr *tar.Header, entry io.Reader) error) error {
	response, err := get(url, githubToken, "application/octet-stream")
	if err != nil {
		return err
	}
	defer response.Body.Close() // mstodo this okay?
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

func get(url string, githubToken string, contentType string) (*http.Response, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", contentType)
	encodedToken := base64.StdEncoding.EncodeToString([]byte(githubToken))
	request.Header.Set("Authorization", "Bearer "+encodedToken)

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
