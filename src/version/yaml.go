// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"fmt"

	uds "github.com/defenseunicorns/uds-cli/src/types"
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	zarf "github.com/zarf-dev/zarf/src/api/v1alpha1"
)

func UpdateYamls(flavor types.Flavor) error {
	packageName, err := updateZarfYaml(flavor)
	if err != nil {
		return err
	}

	return updateBundleYaml(flavor, packageName)
}

func updateZarfYaml(flavor types.Flavor) (packageName string, err error) {
	var zarfPackage zarf.ZarfPackage
	err = utils.LoadYaml("zarf.yaml", &zarfPackage)
	if err != nil {
		return "", err
	}

	zarfPackage.Metadata.Version = flavor.Version

	err = utils.UpdateYaml("zarf.yaml", zarfPackage)
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

	bundle.Metadata.Version = flavor.Version

	// Find the package that matches the package name and update its ref
	for i, bundledPackage := range bundle.Packages {
		if bundledPackage.Name == packageName {
			bundle.Packages[i].Ref = flavor.Version
		}
	}

	err = utils.UpdateYaml("bundle/uds-bundle.yaml", bundle)
	if err != nil {
		return err
	}

	fmt.Printf("Updated uds-bundle.yaml with version %s\n", flavor.Version)
	return nil
}
