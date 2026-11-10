// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"encoding/json"
	"strings"
)

// The component config is the OCI manifest's config blob, rather than a zarf.yaml layer.
const componentConfigMediaType = "application/vnd.zarf.component.config.v1+json"

func ComponentExists(manifestURL, architecture string) (bool, error) {
	const accept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json"
	token := GetAuthToken()
	data, err := getByteArray(manifestURL, token, accept)
	if err != nil {
		return false, err
	}
	var manifest struct {
		Manifests []IndexEntry `json:"manifests"`
		Config    Layer        `json:"config"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return false, err
	}
	if architecture == "" {
		return manifest.Config.MediaType == componentConfigMediaType, nil
	}
	for _, entry := range manifest.Manifests {
		if entry.Platform.Architecture != architecture {
			continue
		}
		childURL := manifestURL[:strings.LastIndex(manifestURL, "/")+1] + entry.Digest
		data, err := getByteArray(childURL, token, accept)
		if err != nil {
			return false, err
		}
		var child struct {
			Config Layer `json:"config"`
		}
		if err := json.Unmarshal(data, &child); err != nil {
			return false, err
		}
		return child.Config.MediaType == componentConfigMediaType, nil
	}
	return false, nil
}
