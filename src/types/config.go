// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package types

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
}
