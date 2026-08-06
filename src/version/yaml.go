// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"fmt"
	"os"
	"path/filepath"
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

type yamlUpdate struct {
	path        string
	displayPath string
	version     string
	content     []byte
	mode        os.FileMode
}

func UpdateYamls(flavor types.Flavor, path, releaseDir string, charts []types.Chart) error {
	zarfUpdate, packageName, err := prepareZarfYamlUpdate(flavor, releaseDir, path)
	if err != nil {
		return err
	}

	chartUpdates, err := prepareChartUpdates(flavor, releaseDir, charts)
	if err != nil {
		return err
	}

	bundleUpdate, err := prepareBundleUpdate(flavor, releaseDir, packageName)
	if err != nil {
		return err
	}

	updates := make([]yamlUpdate, 0, len(chartUpdates)+2)
	updates = append(updates, zarfUpdate)
	if bundleUpdate != nil {
		updates = append(updates, *bundleUpdate)
	}
	for _, update := range chartUpdates {
		updates = append(updates, yamlUpdate{
			path:        update.path,
			displayPath: update.path,
			version:     update.version,
			content:     update.content,
			mode:        update.mode,
		})
	}

	for _, update := range updates {
		err = os.WriteFile(update.path, update.content, update.mode)
		if err != nil {
			return fmt.Errorf("update %s: %w", update.displayPath, err)
		}
		fmt.Printf("Updated %s with version %s\n", update.displayPath, update.version)
	}

	return nil
}

func prepareChartUpdates(flavor types.Flavor, releaseDir string, charts []types.Chart) ([]chartUpdate, error) {
	updates := make([]chartUpdate, 0, len(charts))
	for _, chart := range charts {
		version := chart.Version
		if chart.VersionFromFlavor {
			version = flavor.Version
		}
		chartPath := filepath.Join(releaseDir, chart.Path, "Chart.yaml")
		data, err := os.ReadFile(chartPath)
		if err != nil {
			return nil, fmt.Errorf("read chart %s: %w", chartPath, err)
		}
		info, err := os.Stat(chartPath)
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
			data = []byte(content + "version: " + version + "\n")
		}

		file, err := yamlParser.ParseBytes(data, yamlParser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse chart %s: %w", chartPath, err)
		}
		err = replaceChartValue(file, "$.version", version)
		if err != nil {
			return nil, fmt.Errorf("update chart %s: %w", chartPath, err)
		}
		var out string
		if chart.UpdateAppVersion && metadata.AppVersion == nil {
			out = file.String()
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			out += "appVersion: " + flavor.Version + "\n"
		} else {
			if chart.UpdateAppVersion {
				err = replaceChartValue(file, "$.appVersion", flavor.Version)
				if err != nil {
					return nil, fmt.Errorf("update chart %s: %w", chartPath, err)
				}
			}
			out = file.String()
		}

		updates = append(updates, chartUpdate{path: chartPath, version: version, content: []byte(out), mode: info.Mode()})
	}

	return updates, nil
}

func replaceChartValue(file *ast.File, path, value string) error {
	chartPath, err := goyaml.PathString(path)
	if err != nil {
		return err
	}
	return chartPath.ReplaceWithReader(file, strings.NewReader(value))
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

func prepareZarfYamlUpdate(flavor types.Flavor, releaseDir, path string) (yamlUpdate, string, error) {
	var zarfPackage zarf.ZarfPackage
	zarfPath := filepath.Join(releaseDir, path, "zarf.yaml")
	data, err := os.ReadFile(zarfPath)
	if err != nil {
		return yamlUpdate{}, "", fmt.Errorf("read zarf %s: %w", zarfPath, err)
	}
	info, err := os.Stat(zarfPath)
	if err != nil {
		return yamlUpdate{}, "", fmt.Errorf("stat zarf %s: %w", zarfPath, err)
	}
	err = goyaml.Unmarshal(data, &zarfPackage)
	if err != nil {
		return yamlUpdate{}, "", fmt.Errorf("parse zarf %s: %w", zarfPath, err)
	}

	zarfPackage.Metadata.Version = flavor.Version

	data, err = goyaml.Marshal(zarfPackage)
	if err != nil {
		return yamlUpdate{}, zarfPackage.Metadata.Name, fmt.Errorf("marshal zarf %s: %w", zarfPath, err)
	}

	return yamlUpdate{
		path:        zarfPath,
		displayPath: "zarf.yaml",
		version:     flavor.Version,
		content:     data,
		mode:        info.Mode(),
	}, zarfPackage.Metadata.Name, nil
}

func prepareBundleUpdate(flavor types.Flavor, releaseDir, packageName string) (*yamlUpdate, error) {
	var bundle uds.UDSBundle
	bundlePath := filepath.Join(releaseDir, "bundle", "uds-bundle.yaml")
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read bundle %s: %w", bundlePath, err)
	}
	info, err := os.Stat(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("stat bundle %s: %w", bundlePath, err)
	}
	err = goyaml.Unmarshal(data, &bundle)
	if err != nil {
		return nil, fmt.Errorf("parse bundle %s: %w", bundlePath, err)
	}

	tag := utils.JoinNonEmpty("-", flavor.Version, flavor.Name)

	bundle.Metadata.Version = tag

	// Find the package that matches the package name and update its ref
	for i, bundledPackage := range bundle.Packages {
		if bundledPackage.Name == packageName {
			bundle.Packages[i].Ref = tag
		}
	}

	data, err = goyaml.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshal bundle %s: %w", bundlePath, err)
	}

	return &yamlUpdate{
		path:        bundlePath,
		displayPath: "uds-bundle.yaml",
		version:     tag,
		content:     data,
		mode:        info.Mode(),
	}, nil
}
