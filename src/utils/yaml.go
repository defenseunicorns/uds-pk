// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/types"
	goyaml "github.com/goccy/go-yaml"
)

func LoadReleaseConfig(dir string) (types.ReleaseConfig, error) {

	var config types.ReleaseConfig
	err := LoadYaml(filepath.Join(dir, "/releaser.yaml"), &config)
	if err != nil {
		return types.ReleaseConfig{}, err
	}
	err = config.VerifyReleaseConfig()
	if err != nil {
		return types.ReleaseConfig{}, err
	}

	return config, nil
}

func LoadYaml(path string, destVar any) error {
	// mstodo: drop this
	if strings.HasPrefix(path, "/") {
		fmt.Println("WARNING: Loading YAML from a path that starts with a slash. This is not recommended.")
		debug.PrintStack()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return goyaml.Unmarshal(data, destVar)
}

func UpdateYaml(path string, srcVar any) error {
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
