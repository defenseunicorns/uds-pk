// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	uds "github.com/defenseunicorns/uds-cli/src/types"
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	goyaml "github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	yamlParser "github.com/goccy/go-yaml/parser"
	zarf "github.com/zarf-dev/zarf/src/api/v1alpha1"
)

type chartMetadata struct {
	Version    *string `yaml:"version"`
	AppVersion *string `yaml:"appVersion"`
}

type chartUpdate struct {
	path    string
	version string
	content []byte
	mode    os.FileMode
}

func UpdateYamls(flavor types.Flavor, path, releaseDir string, charts []types.Chart) error {
	chartUpdates, err := prepareChartUpdates(flavor, releaseDir, charts)
	if err != nil {
		return err
	}

	packageName, err := updateZarfYaml(flavor, path)
	if err != nil {
		return err
	}
	err = updateBundleYaml(flavor, packageName)
	if err != nil {
		return err
	}

	for _, update := range chartUpdates {
		err = os.WriteFile(update.path, update.content, update.mode)
		if err != nil {
			return fmt.Errorf("update chart %s: %w", update.path, err)
		}
		fmt.Printf("Updated %s with version %s\n", update.path, update.version)
	}

	return nil
}

func prepareChartUpdates(flavor types.Flavor, releaseDir string, charts []types.Chart) ([]chartUpdate, error) {
	updates := make([]chartUpdate, 0, len(charts))
	for _, chart := range charts {
		var data []byte
		var info os.FileInfo
		var file *ast.File
		var err error

		version := chart.Version
		if chart.VersionFromFlavor {
			version = flavor.Version
		}
		chartPath := filepath.Join(releaseDir, chart.Path, "Chart.yaml")
		data, err = os.ReadFile(chartPath)
		if err != nil {
			return nil, fmt.Errorf("read chart %s: %w", chartPath, err)
		}
		info, err = os.Stat(chartPath)
		if err != nil {
			return nil, fmt.Errorf("stat chart %s: %w", chartPath, err)
		}

		var metadata chartMetadata
		err = goyaml.Unmarshal(data, &metadata)
		if err != nil {
			return nil, fmt.Errorf("parse chart %s: %w", chartPath, err)
		}
		if metadata.Version == nil {
			content := string(data)
			if !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			data = []byte(content + "version: " + strconv.Quote(version) + "\n")
		}

		file, err = yamlParser.ParseBytes(data, yamlParser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse chart %s: %w", chartPath, err)
		}
		err = replaceChartValue(file, "$.version", version)
		if err != nil {
			return nil, fmt.Errorf("update chart %s: %w", chartPath, err)
		}
		if chart.UpdateAppVersion {
			if metadata.AppVersion == nil {
				content := file.String()
				if !strings.HasSuffix(content, "\n") {
					content += "\n"
				}
				content += "appVersion: " + strconv.Quote(flavor.Version) + "\n"
				updates = append(updates, chartUpdate{path: chartPath, version: version, content: []byte(content), mode: info.Mode()})
				continue
			}
			err = replaceChartValue(file, "$.appVersion", flavor.Version)
			if err != nil {
				return nil, fmt.Errorf("update chart %s: %w", chartPath, err)
			}
		}

		updates = append(updates, chartUpdate{path: chartPath, version: version, content: []byte(file.String()), mode: info.Mode()})
	}

	return updates, nil
}

func replaceChartValue(file *ast.File, path, value string) error {
	chartPath, err := goyaml.PathString(path)
	if err != nil {
		return err
	}
	return chartPath.ReplaceWithReader(file, strings.NewReader(strconv.Quote(value)))
}

func UpdateBundleYamlOnly(bundle types.Bundle) error {
	var udsBundle uds.UDSBundle
	bundlePath := filepath.Join(bundle.Path, "uds-bundle.yaml")
	err := utils.LoadYaml(bundlePath, &udsBundle)
	if err != nil {
		return err
	}

	udsBundle.Metadata.Version = bundle.Version

	err = utils.UpdateYaml(bundlePath, udsBundle)
	if err != nil {
		return err
	}

	fmt.Printf("Updated uds-bundle.yaml with version %s\n", bundle.Version)
	return nil
}

func updateZarfYaml(flavor types.Flavor, path string) (packageName string, err error) {
	var zarfPackage zarf.ZarfPackage
	zarfPath := filepath.Join(path, "zarf.yaml")
	err = utils.LoadYaml(zarfPath, &zarfPackage)
	if err != nil {
		return "", err
	}

	zarfPackage.Metadata.Version = flavor.Version

	err = utils.UpdateYaml(zarfPath, zarfPackage)
	if err != nil {
		return zarfPackage.Metadata.Name, err
	}

	fmt.Printf("Updated zarf.yaml with version %s\n", flavor.Version)

	return zarfPackage.Metadata.Name, nil
}

func updateBundleYaml(flavor types.Flavor, packageName string) error {
	var bundle uds.UDSBundle
	err := utils.LoadYaml("bundle/uds-bundle.yaml", &bundle)
	if err != nil {
		return err
	}

	tag := utils.JoinNonEmpty("-", flavor.Version, flavor.Name)

	bundle.Metadata.Version = tag

	// Find the package that matches the package name and update its ref
	for i, bundledPackage := range bundle.Packages {
		if bundledPackage.Name == packageName {
			bundle.Packages[i].Ref = tag
		}
	}

	err = utils.UpdateYaml("bundle/uds-bundle.yaml", bundle)
	if err != nil {
		return err
	}

	fmt.Printf("Updated uds-bundle.yaml with version %s\n", tag)
	return nil
}
