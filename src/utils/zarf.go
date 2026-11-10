// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"os"

	"github.com/defenseunicorns/uds-pk/src/zarf"
)

func GetPackageName() (string, error) {
	data, err := os.ReadFile("zarf.yaml")
	if err != nil {
		return "", err
	}

	metadata, err := zarf.ReadMetadata(data)
	if err != nil {
		return "", err
	}
	return metadata.Name, nil
}
