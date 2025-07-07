// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package platforms

import (
	"fmt"
	"os"

	"regexp"

	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
)

type Platform interface {
	TagAndRelease(flavor types.Flavor, tokenVarName string) error
}

func LoadAndTag(releaseDir, flavor, tokenVarName string, platform Platform) error {
	return LoadAndTagWithValidation(releaseDir, flavor, tokenVarName, platform, true)
}

func LoadAndTagWithValidation(releaseDir, flavor, tokenVarName string, platform Platform, enableValidation bool) error {
	err := VerifyEnvVar(tokenVarName)
	if err != nil {
		return err
	}

	releaseConfig, err := utils.LoadReleaseConfigWithValidation(releaseDir, enableValidation)
	if err != nil {
		return err
	}

	currentFlavor, err := utils.GetFlavorConfig(flavor, releaseConfig)
	if err != nil {
		return err
	}

	return platform.TagAndRelease(currentFlavor, tokenVarName)
}

func VerifyEnvVar(varName string) error {
	if value, exists := os.LookupEnv(varName); !exists || value == "" {
		return fmt.Errorf("%s is unset or empty", varName)
	}

	return nil
}

func ReleaseExists(expectedStatusCode, receivedStatusCode int, err error, pattern string, packageName string, flavor types.Flavor) error {
	if err != nil {
		if receivedStatusCode == expectedStatusCode && regexp.MustCompile(pattern).MatchString(err.Error()) {
			fmt.Printf("Release with tag %s-%s already exists\n", flavor.Version, flavor.Name)
			return nil
		} else {
			fmt.Println("Error creating release: ", err)
			return err
		}
	} else {
		fmt.Printf("Release %s %s-%s created\n", packageName, flavor.Version, flavor.Name)
		return nil
	}
}
