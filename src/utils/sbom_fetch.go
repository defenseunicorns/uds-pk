// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	MediaType   string            `json:"mediaType"`
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

// FetchSboms retrieves legacy archive-backed and beta granular SBOMs from a Zarf OCI package.
func FetchSboms(repoOwner, packageUrl, tag string, outputDir string, logger *slog.Logger) ([]string, error) {
	base := "https://ghcr.io/v2/" + repoOwner + "/" + packageUrl
	authToken := GetAuthToken()
	manifest, err := fetchSBOMManifest(base, tag, authToken)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}
	var files []string
	for _, layer := range manifest.Layers {
		title := layer.Annotations["org.opencontainers.image.title"]
		blobURL := base + "/blobs/" + layer.Digest
		if title == "sboms.tar" {
			err := walkRemoteTarArchive(blobURL, authToken, logger, func(header *tar.Header, entry io.Reader) error {
				if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".json") {
					return nil
				}
				// Flatten legacy archive paths for the scanner; reject ambiguous names instead of overwriting.
				file, err := writeSBOM(outputDir, filepath.Base(header.Name), entry)
				if err != nil {
					return err
				}
				files = append(files, file)
				return nil
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		if layer.Annotations["dev.zarf.resource.kind"] != "sbom" {
			continue
		}
		if layer.MediaType != "application/vnd.syft+json" ||
			(!strings.HasPrefix(title, "sboms/images/") && !strings.HasPrefix(title, "sboms/files/")) ||
			!strings.HasSuffix(title, ".json") {
			return nil, fmt.Errorf("invalid Zarf SBOM layer %q", title)
		}
		data, err := getByteArray(blobURL, authToken, layer.MediaType)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if layer.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
			return nil, fmt.Errorf("SBOM layer %q digest mismatch", title)
		}
		if !json.Valid(data) {
			return nil, fmt.Errorf("SBOM layer %q is not JSON", title)
		}
		// Hash the full resource path to avoid collisions and filesystem limits on long image names.
		filename := fmt.Sprintf("%x.json", sha256.Sum256([]byte(title)))
		file, err := writeSBOM(outputDir, filename, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no SBOMs found in Zarf package %s:%s", packageUrl, tag)
	}
	return files, nil
}

func fetchSBOMManifest(base, ref, authToken string) (ImageManifest, error) {
	const accept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json"
	data, err := getByteArray(base+"/manifests/"+ref, authToken, accept)
	if err != nil {
		return ImageManifest{}, err
	}
	var root struct {
		Manifests []IndexEntry `json:"manifests"`
		Layers    []Layer      `json:"layers"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return ImageManifest{}, err
	}
	if root.Layers != nil {
		return ImageManifest{Layers: root.Layers}, nil
	}
	if len(root.Manifests) == 0 {
		return ImageManifest{}, fmt.Errorf("package OCI index has no manifests")
	}
	// Retain the existing first-platform behavior; architecture selection is a separate concern.
	data, err = getByteArray(base+"/manifests/"+root.Manifests[0].Digest, authToken, accept)
	if err != nil {
		return ImageManifest{}, err
	}
	var manifest ImageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ImageManifest{}, err
	}
	return manifest, nil
}

func writeSBOM(outputDir, name string, data io.Reader) (_ string, err error) {
	filePath := filepath.Join(outputDir, name)
	out, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	if _, err := io.Copy(out, data); err != nil {
		return "", err
	}
	return filePath, nil
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
		_ = response.Body.Close()
		return nil, errors.New("unexpected status code: " + response.Status)
	}
	return response, nil
}
