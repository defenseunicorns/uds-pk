// Copyright 2024-2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/zarf"
)

func GetPackageName() (string, error) {
	return GetSourceName("zarf.yaml")
}

func GetSourceName(source string) (string, error) {
	if source == "" {
		source = "zarf.yaml"
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}

	metadata, err := zarf.ReadMetadata(data)
	if err != nil {
		return "", err
	}
	return metadata.Name, nil
}

func ReleaseSourcePath(releaseDir, packagePath string, flavor types.Flavor) (string, error) {
	source := flavor.Source
	if source == "" {
		source = "zarf.yaml"
	}
	clean := filepath.Clean(source)
	if filepath.IsAbs(source) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("release source must be within the selected package directory: %s", source)
	}
	return filepath.Join(releaseDir, packagePath, source), nil
}

func LoadReleaseSource(releaseDir, packagePath string, flavor types.Flavor) (string, zarf.Definition, error) {
	source, err := ReleaseSourcePath(releaseDir, packagePath, flavor)
	if err != nil {
		return "", zarf.Definition{}, err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return "", zarf.Definition{}, err
	}
	definition, err := zarf.ReadDefinition(data)
	if err != nil {
		return "", zarf.Definition{}, fmt.Errorf("read release source %s: %w", source, err)
	}
	if definition.IsComponent() {
		if definition.Variant.Flavor != flavor.Name {
			return "", zarf.Definition{}, fmt.Errorf("component variant flavor %q does not match release flavor %q", definition.Variant.Flavor, flavor.Name)
		}
		switch definition.Variant.Architecture {
		case "", "amd64", "arm64":
		default:
			return "", zarf.Definition{}, fmt.Errorf("unsupported component variant architecture %q", definition.Variant.Architecture)
		}
	}
	return source, definition, nil
}
