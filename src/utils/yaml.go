// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseunicorns/uds-pk/src/types"
	goyaml "github.com/goccy/go-yaml"
)

func LoadReleaseConfig(dir string) (types.ReleaseConfig, error) {

	var config types.ReleaseConfig
	err := LoadYaml(filepath.Join(dir, "/releaser.yaml"), &config)
	if err != nil {
		return types.ReleaseConfig{}, err
	}

	// Validate that all flavor versions are semver compliant
	for _, flavor := range config.Flavors {
		if err := ValidateSemver(flavor.Version); err != nil {
			return types.ReleaseConfig{}, fmt.Errorf("flavor '%s': %w", flavor.Name, err)
		}
	}

	return config, nil
}

func LoadYaml(path string, destVar interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return goyaml.Unmarshal(data, destVar)
}

func UpdateYaml(path string, srcVar interface{}) error {
	data, err := goyaml.Marshal(srcVar)
	if err != nil {
		return err
	}

	yamlInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, yamlInfo.Mode())
}
