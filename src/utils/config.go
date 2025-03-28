// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"errors"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/types"
)

func GetFlavorConfig(flavor string, config types.ReleaseConfig, packageName string) (string, types.Flavor, error) {
	if packageName != "" {
		for _, pkg := range config.Packages {
			if pkg.Name == packageName {
				f, err := parseFlavor(flavor, pkg.Flavors)
				return pkg.Path, f, err
			}
		}
		return "", types.Flavor{}, errors.New("package not found")
	} else {
		f, err := parseFlavor(flavor, config.Flavors)
		return "", f, err
	}
}

func GetFormattedVersion(packageName string, version string, flavor string) string {
	if packageName != "" {
		return strings.Join([]string{packageName, version, flavor}, "-")
	} else {
		return strings.Join([]string{version, flavor}, "-")
	}
}

func parseFlavor(flavor string, flavors []types.Flavor) (types.Flavor, error) {
	for _, f := range flavors {
		if f.Name == flavor {
			return f, nil
		}
	}
	return types.Flavor{}, errors.New("flavor not found")
}
