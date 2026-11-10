// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package scan

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/distribution/reference"
)

const identityProperty = "uds-pk:scan-identity"

// Identity keeps image and platform information independent of display filenames.
type Identity struct {
	Reference string `json:"reference,omitempty"`
	Platform  string `json:"platform,omitempty"`
	ImageID   string `json:"imageID,omitempty"`
	SourceID  string `json:"sourceID,omitempty"`
}

func ImageIdentity(image string) (Identity, error) {
	image = strings.TrimPrefix(strings.TrimPrefix(image, "registry:"), "docker:")
	image = strings.TrimPrefix(image, "https://")
	if strings.HasPrefix(image, "registry.hub.docker.com/") {
		image = "docker.io/" + strings.TrimPrefix(image, "registry.hub.docker.com/")
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return Identity{}, fmt.Errorf("invalid image reference %q: %w", image, err)
	}
	return Identity{Reference: reference.TagNameOnly(named).String()}, nil
}

func (i Identity) Repository() string {
	named, err := reference.ParseNormalizedNamed(i.Reference)
	if err != nil {
		return ""
	}
	return reference.TrimNamed(named).String()
}

// Equivalent requires the same platform and immutable image ID, known platform/reference,
// or identical source bytes. Unknown-platform SBOMs from distinct resources remain distinct.
func (i Identity) Equivalent(other Identity) bool {
	if i.Repository() != other.Repository() || (i.Platform != "" && other.Platform != "" && i.Platform != other.Platform) {
		return false
	}
	if i.ImageID != "" && other.ImageID != "" {
		return i.ImageID == other.ImageID
	}
	if i.Platform != other.Platform {
		return false
	}
	if i.SourceID != "" && i.SourceID == other.SourceID {
		return true
	}
	return i.Platform != "" && i.Reference == other.Reference
}

func sbomIdentity(file string) (Identity, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return Identity{}, err
	}
	var sbom struct {
		Source struct {
			Metadata struct {
				UserInput    string `json:"userInput"`
				ID           string `json:"id"`
				ImageID      string `json:"imageID"`
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
				Variant      string `json:"variant"`
			} `json:"metadata"`
		} `json:"source"`
	}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return Identity{}, fmt.Errorf("read SBOM identity %s: %w", file, err)
	}
	metadata := sbom.Source.Metadata
	identity, _ := ImageIdentity(metadata.UserInput)
	identity.SourceID = fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	identity.ImageID = metadata.ID
	if identity.ImageID == "" {
		identity.ImageID = metadata.ImageID
	}
	if metadata.Architecture != "" {
		identity.Platform = strings.Trim(strings.Join([]string{metadata.OS, metadata.Architecture, metadata.Variant}, "/"), "/")
	}
	return identity, nil
}

type identityEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// recordIdentity adds one standard CycloneDX metadata property without dropping unknown fields.
func recordIdentity(file string, identity Identity) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("read Grype output %s: %w", file, err)
	}
	if root == nil {
		return fmt.Errorf("grype output %s is not a JSON object", file)
	}
	metadata := map[string]json.RawMessage{}
	if raw := root["metadata"]; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return err
		}
	}
	var properties []json.RawMessage
	if raw := metadata["properties"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &properties); err != nil {
			return err
		}
	}
	value, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	entry, err := json.Marshal(identityEntry{Name: identityProperty, Value: string(value)})
	if err != nil {
		return err
	}
	var kept []json.RawMessage
	for _, raw := range properties {
		var prop identityEntry
		if err := json.Unmarshal(raw, &prop); err != nil {
			return err
		}
		if prop.Name != identityProperty {
			kept = append(kept, raw)
		}
	}
	metadata["properties"], err = json.Marshal(append(kept, entry))
	if err != nil {
		return err
	}
	root["metadata"], err = json.Marshal(metadata)
	if err != nil {
		return err
	}
	data, err = json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, append(data, '\n'), 0o600)
}

func ReadIdentity(file string) (Identity, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return Identity{}, err
	}
	var root struct {
		Metadata struct {
			Properties []identityEntry `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return Identity{}, err
	}
	for _, entry := range root.Metadata.Properties {
		if entry.Name == identityProperty {
			var identity Identity
			if err := json.Unmarshal([]byte(entry.Value), &identity); err != nil {
				return Identity{}, err
			}
			return identity, nil
		}
	}
	return Identity{}, fmt.Errorf("scan %s has no image identity", file)
}
