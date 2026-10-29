// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"fmt"

	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
)

// Selection identifies one release target using the existing release selectors.
type Selection struct {
	Package string
	Bundle  string
	Flavor  string
}

// releaseTarget describes a configured release without creating or updating it.
type releaseTarget struct {
	Kind    string
	Name    string
	Flavor  string
	Version string
	Tag     string
	// Paths are relative to the release directory. An empty list means the
	// entire repository, as used for root releases.
	Paths []string
}

// resolveTarget reuses release configuration selection and tag conventions.
// The caller loads and validates config before selecting a target.
func resolveTarget(config types.ReleaseConfig, selection Selection) (releaseTarget, error) {
	if selection.Bundle != "" {
		if selection.Package != "" || selection.Flavor != "" {
			return releaseTarget{}, fmt.Errorf("bundle selection cannot be combined with a package or flavor")
		}
		bundle, err := utils.GetBundleConfig(config, selection.Bundle)
		if err != nil {
			return releaseTarget{}, err
		}
		return releaseTarget{
			Kind: "bundle", Name: bundle.Name, Version: bundle.Version,
			Tag:   utils.GetFormattedVersion(bundle.Name, bundle.Version, ""),
			Paths: []string{bundle.Path},
		}, nil
	}

	packagePath, flavor, err := utils.GetFlavorConfig(selection.Flavor, config, selection.Package)
	if err != nil {
		return releaseTarget{}, fmt.Errorf("select release target: %w", err)
	}
	target := releaseTarget{
		Kind: "root", Name: selection.Package, Flavor: flavor.Name, Version: flavor.Version,
		Tag: utils.GetFormattedVersion(selection.Package, flavor.Version, flavor.Name),
	}
	if selection.Package == "" {
		return target, nil
	}

	target.Kind = "package"
	target.Paths = []string{packagePath}
	charts, err := utils.GetCharts(config, selection.Package)
	if err != nil {
		return releaseTarget{}, err
	}
	for _, chart := range charts {
		target.Paths = append(target.Paths, chart.Path)
	}
	return target, nil
}
