// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zarf-dev/zarf/src/api/v1alpha1"
)

func TestGetImages(t *testing.T) {
	pkg := v1alpha1.ZarfPackage{
		Components: []v1alpha1.ZarfComponent{
			{
				Name: "first-registry-one-component",
				Only: v1alpha1.ZarfComponentOnlyTarget{
					Flavor: "registry1",
				},
				Images: []string{"registry.example/direct:1.0.0"},
				ImageArchives: []v1alpha1.ImageArchive{
					{
						Path: "images-1.tar",
						Images: []string{
							"registry.example/archive-one:1.0.0",
							"registry.example/archive-two:1.0.0",
						},
					},
				},
			},
			{
				Name: "second-registry-one-component",
				Only: v1alpha1.ZarfComponentOnlyTarget{
					Flavor: "registry1",
				},
				ImageArchives: []v1alpha1.ImageArchive{
					{
						Path:   "images-2.tar",
						Images: []string{"registry.example/archive-three:1.0.0"},
					},
				},
			},
			{
				Name: "registry-two-component",
				Only: v1alpha1.ZarfComponentOnlyTarget{
					Flavor: "registry2",
				},
				Images: []string{"registry.example/registry-two:1.0.0"},
			},
			{
				Name:   "unflavored-component",
				Images: []string{"registry.example/unflavored:1.0.0"},
			},
		},
	}

	require.Equal(t, map[string][]string{
		"registry1": {
			"registry.example/direct:1.0.0",
			"registry.example/archive-one:1.0.0",
			"registry.example/archive-two:1.0.0",
			"registry.example/archive-three:1.0.0",
		},
		"registry2": {"registry.example/registry-two:1.0.0"},
	}, getImages(&pkg))
}
