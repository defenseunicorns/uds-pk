// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package types

import "testing"

func TestVerifyReleaseConfig(t *testing.T) {
	validNamedFlavor := Flavor{
		Name:    "unicorn",
		Version: "1.0.0-uds.0",
	}
	validFlavorlessFlavor := Flavor{
		Name:    "",
		Version: "1.0.0-flavorless.0",
	}
	validPublishBundleFlavor := Flavor{
		Name:             "unicorn",
		Version:          "1.0.0-uds.0",
		PublishBundle:    true,
		PublishBundleUrl: "https://example.com/bundle.tar.gz",
	}
	invalidPublishBundleFlavor := Flavor{
		Name:             "unicorn",
		Version:          "1.0.0-uds.0",
		PublishBundle:    true,
		PublishBundleUrl: "",
	}
	invalidVersionlessFlavor := Flavor{
		Name:    "unicorn",
		Version: "",
	}
	tests := []struct {
		name        string
		config      ReleaseConfig
		expectError bool
	}{
		{
			name: "valid config with named flavor",
			config: ReleaseConfig{
				Flavors: []Flavor{validNamedFlavor},
			},
			expectError: false,
		},
		{
			name: "valid config with flavorless flavor",
			config: ReleaseConfig{
				Flavors: []Flavor{validFlavorlessFlavor},
			},
			expectError: false,
		},
		{
			name: "valid config with package",
			config: ReleaseConfig{
				Packages: []Package{
					{
						Name:    "test-package",
						Path:    "test/path",
						Flavors: []Flavor{validNamedFlavor},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid config with base flavor and package",
			config: ReleaseConfig{
				Flavors: []Flavor{validNamedFlavor},
				Packages: []Package{
					{
						Name:    "test-package",
						Path:    "test/path",
						Flavors: []Flavor{validNamedFlavor},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid config with base flavor and package with flavorless",
			config: ReleaseConfig{
				Flavors: []Flavor{validNamedFlavor},
				Packages: []Package{
					{
						Name:    "test-package",
						Path:    "test/path",
						Flavors: []Flavor{validFlavorlessFlavor},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid config with no flavors or packages",
			config: ReleaseConfig{
				Flavors:  []Flavor{},
				Packages: []Package{},
			},
			expectError: true,
		},
		{
			name: "invalid config with flavor without version",
			config: ReleaseConfig{
				Flavors: []Flavor{invalidVersionlessFlavor},
			},
			expectError: true,
		},
		{
			name: "invalid config with package without name",
			config: ReleaseConfig{
				Packages: []Package{
					{
						Path:    "test/path",
						Flavors: []Flavor{validNamedFlavor},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid config with package without path",
			config: ReleaseConfig{
				Packages: []Package{
					{
						Name:    "test-package",
						Flavors: []Flavor{validNamedFlavor},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid config with duplicate named flavors",
			config: ReleaseConfig{
				Flavors: []Flavor{
					validNamedFlavor,
					validNamedFlavor, // Duplicate
				},
			},
			expectError: true,
		},
		{
			name: "invalid config with duplicate named flavors in package",
			config: ReleaseConfig{
				Packages: []Package{
					{
						Name: "test-package",
						Path: "test/path",
						Flavors: []Flavor{
							validNamedFlavor,
							validNamedFlavor, // Duplicate
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid config with duplicate unnamed flavors",
			config: ReleaseConfig{
				Flavors: []Flavor{
					validFlavorlessFlavor,
					validFlavorlessFlavor, // Duplicate
				},
			},
			expectError: true,
		},
		{
			name: "invalid config with package without flavors",
			config: ReleaseConfig{
				Packages: []Package{
					{
						Name: "test-package",
						Path: "test/path",
					},
				},
			},
			expectError: true,
		},
		{
			name: "valid config with publish bundle true",
			config: ReleaseConfig{
				Flavors: []Flavor{validPublishBundleFlavor},
			},
			expectError: false,
		},
		{
			name: "invalid config with publish bundle true but no URL",
			config: ReleaseConfig{
				Flavors: []Flavor{invalidPublishBundleFlavor},
			},
			expectError: true,
		},
		{
			name: "valid config with package publish bundle true",
			config: ReleaseConfig{
				Packages: []Package{
					{
						Name:    "test-package",
						Path:    "test/path",
						Flavors: []Flavor{validPublishBundleFlavor},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid config with package publish bundle true but no URL",
			config: ReleaseConfig{
				Packages: []Package{
					{
						Name:    "test-package",
						Path:    "test/path",
						Flavors: []Flavor{invalidPublishBundleFlavor},
					},
				},
			},
			expectError: true,
		},
		{
			name: "valid config with a single bundle",
			config: ReleaseConfig{
				Bundles: []Bundle{
					{
						Name:    "test-bundle",
						Path: 	"test/bundle",
						Version: "1.0.0-bundle.0",
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid config with a bundle missing name",
			config: ReleaseConfig{
				Bundles: []Bundle{
					{
						Path: 	"test/bundle",
						Version: "1.0.0-bundle.0",
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid config with a bundle missing version",
			config: ReleaseConfig{
				Bundles: []Bundle{
					{
						Name:    "test-bundle",
						Path: 	"test/bundle",
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid config with a bundle missing path",
			config: ReleaseConfig{
				Bundles: []Bundle{
					{
						Name:    "test-bundle",
						Version: "1.0.0-bundle.0",
					},
				},
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.VerifyReleaseConfig()
			if test.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %s", err)
				}
			}
		})
	}

}
