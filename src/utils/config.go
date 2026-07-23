// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"errors"
	"fmt"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/types"
)

var ErrPackageNotFound = errors.New("package not found")

func GetFlavorConfig(flavor string, config types.ReleaseConfig, packageName string) (string, types.Flavor, error) {
	if packageName == "" {
		f, err := parseFlavor(flavor, config.Flavors)
		return "", f, err
	}

	pkg, err := getPackage(config, packageName)
	if err != nil {
		return "", types.Flavor{}, err
	}
	f, err := parseFlavor(flavor, pkg.Flavors)
	return pkg.Path, f, err
}

func GetCharts(config types.ReleaseConfig, packageName string) ([]types.Chart, error) {
	if packageName == "" {
		return config.Charts, nil
	}

	pkg, err := getPackage(config, packageName)
	if err != nil {
		return nil, err
	}
	return pkg.Charts, nil
}

func getPackage(config types.ReleaseConfig, packageName string) (*types.Package, error) {
	for i := range config.Packages {
		if config.Packages[i].Name == packageName {
			return &config.Packages[i], nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrPackageNotFound, packageName)
}

func GetFormattedVersion(packageName string, version string, flavor string) string {
	return JoinNonEmpty("-", packageName, version, flavor)
}

func GetBundleConfig(config types.ReleaseConfig, bundleName string) (types.Bundle, error) {
	for _, b := range config.Bundles {
		if b.Name == bundleName {
			return b, nil
		}
	}
	return types.Bundle{}, fmt.Errorf("bundle %s is not defined in releaser.yaml", bundleName)
}

func parseFlavor(flavor string, flavors []types.Flavor) (types.Flavor, error) {
	for _, f := range flavors {
		if f.Name == flavor {
			return f, nil
		}
	}
	return types.Flavor{}, errors.New("flavor not found")
}

// JoinNonEmpty works like strings.Join but drops any empty elements.
func JoinNonEmpty(sep string, elems ...string) string {
	var nonEmptyStrings []string
	for _, s := range elems {
		if s != "" {
			nonEmptyStrings = append(nonEmptyStrings, s)
		}
	}
	return strings.Join(nonEmptyStrings, sep)
}
