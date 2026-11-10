// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComponentExists(t *testing.T) {
	for _, test := range []struct {
		name, architecture, manifest, child string
		exists                              bool
	}{
		{"generic", "", `{"config":{"mediaType":"application/vnd.zarf.component.config.v1+json"}}`, "", true},
		{"generic is not indexed", "arm64", `{"config":{"mediaType":"application/vnd.zarf.component.config.v1+json"}}`, "", false},
		{"package manifest", "", `{"config":{"mediaType":"application/vnd.zarf.config.v1+json"}}`, "", false},
		{"arm variant", "arm64", `{"manifests":[{"digest":"sha256:arm","platform":{"architecture":"arm64"}}]}`, `{"config":{"mediaType":"application/vnd.zarf.component.config.v1+json"}}`, true},
		{"wrong arch", "amd64", `{"manifests":[{"digest":"sha256:arm","platform":{"architecture":"arm64"}}]}`, "", false},
		{"variant is not generic", "", `{"manifests":[{"digest":"sha256:arm","platform":{"architecture":"arm64"}}]}`, "", false},
		{"indexed package is not a component", "arm64", `{"manifests":[{"digest":"sha256:arm","platform":{"architecture":"arm64"}}]}`, `{"config":{"mediaType":"application/vnd.zarf.config.v1+json"}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mockSBOMRegistry(t, map[string][]byte{"manifests/v1": []byte(test.manifest), "manifests/sha256:arm": []byte(test.child)})
			exists, err := ComponentExists("https://ghcr.io/v2/test/app/manifests/v1", test.architecture)
			require.NoError(t, err)
			require.Equal(t, test.exists, exists)
		})
	}
}
