// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package types

import (
	"errors"
	"fmt"
)

type Flavor struct {
	Name              string `yaml:"name"`
	Version           string `yaml:"version"`
	PublishBundle     bool   `yaml:"publishBundle,omitempty,default=false"`
	PublishPackageUrl string `yaml:"publishPackageUrl"`
	PublishBundleUrl  string `yaml:"publishBundleUrl,omitempty"`
}

type Package struct {
	Name    string   `yaml:"name"`
	Path    string   `yaml:"path"`
	Flavors []Flavor `yaml:"flavors"`
}

type ReleaseConfig struct {
	Flavors  []Flavor  `yaml:"flavors"`
	Packages []Package `yaml:"packages,omitempty"`
	Bundles  []Bundle  `yaml:"bundles,omitempty"`
}

type Bundle struct {
	Name    string   `yaml:"name"`
	Path    string   `yaml:"path"`
	Version string   `yaml:"version"`
}

func (config ReleaseConfig)VerifyReleaseConfig() error {
	// There must be at least one flavor or package defined
	if len(config.Flavors) == 0 && len(config.Packages) == 0 && len(config.Bundles) == 0 {
		return errors.New("releaser.yaml must define at least one flavor, package, or bundle")
	}

	// Each flavor must have a version defined
	for _, flavor := range config.Flavors {
		if flavor.Version == "" {
			return errors.New("each flavor must have a version defined")
		}
	}
	for _, pkg := range config.Packages {
		for _, flavor := range pkg.Flavors {
			if flavor.Version == "" {
				return errors.New("each flavor in a package must have a version defined")
			}
		}
	}

	// Each package must have a name and path defined
	for _, pkg := range config.Packages {
		if pkg.Name == "" {
			return errors.New("each package must have a name defined")
		}
		if pkg.Path == "" {
			return errors.New("each package must have a path defined")
		}
	}

	// There must not be more than one flavor with the same name per package
	flavorNames := make(map[string]bool)
	for _, flavor := range config.Flavors {
		if _, exists := flavorNames[flavor.Name]; exists {
			return errors.New("flavor names must be unique")
		}
		flavorNames[flavor.Name] = true
	}
	for _, pkg := range config.Packages {
		for k := range flavorNames {
			delete(flavorNames, k)
		}
		for _, flavor := range pkg.Flavors {
			if _, exists := flavorNames[flavor.Name]; exists {
				return errors.New("flavor names must be unique within a package")
			}
			flavorNames[flavor.Name] = true
		}
	}

	// If publishBundle is true anywhere print a not implemented warning
	for _, flavor := range config.Flavors {
		if flavor.PublishBundle {
			fmt.Println("Warning: publishBundle is not implemented yet.")
			break
		}
	}
	for _, pkg := range config.Packages {
		for _, flavor := range pkg.Flavors {
			if flavor.PublishBundle {
				fmt.Println("Warning: publishBundle is not implemented yet.")
				break
			}
		}
	}

	// Each package must have at least one flavor defined
	for _, pkg := range config.Packages {
		if len(pkg.Flavors) == 0 {
			return errors.New("each package must have at least one flavor defined")
		}
	}

	// Each flavor must have a publishBundleUrl if publishBundle is true
	for _, flavor := range config.Flavors {
		if flavor.PublishBundle && flavor.PublishBundleUrl == "" {
			return errors.New("if publishBundle is true, publishBundleUrl must be defined")
		}
	}
	for _, pkg := range config.Packages {
		for _, flavor := range pkg.Flavors {
			if flavor.PublishBundle && flavor.PublishBundleUrl == "" {
				return errors.New("if publishBundle is true, publishBundleUrl must be defined")
			}
		}
	}

	// Each bundle must have a name, path, and version defined
	for _, bundle := range config.Bundles {
		if bundle.Name == "" {
			return errors.New("each bundle must have a name defined")
		}
		if bundle.Path == "" {
			return errors.New("each bundle must have a path defined")
		}
		if bundle.Version == "" {
			return errors.New("each bundle must have a version defined")
		}
	}

	return nil
}
