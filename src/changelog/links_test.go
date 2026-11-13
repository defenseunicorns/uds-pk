// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepositoryLinks(t *testing.T) {
	tests := []struct {
		remote string
		base   string
		prefix string
	}{
		{"https://github.com/example/project.git", "https://github.com/example/project", ""},
		{"git@github.com:example/project.git", "https://github.com/example/project", ""},
		{"ssh://git@github.com:22/example/project.git", "https://github.com/example/project", ""},
		{"git://github.com/example/project.git", "https://github.com/example/project", ""},
		{"https://name:secret@github.com/example/project.git?token=secret#secret", "https://github.com/example/project", ""},
		{"https://gitlab.com/group/subgroup/project.git", "https://gitlab.com/group/subgroup/project", "/-"},
		{"git@gitlab.example.test:group/subgroup/project.git", "https://gitlab.example.test/group/subgroup/project", "/-"},
		{"https://gitlab.example.test:8443/group/project.git", "https://gitlab.example.test:8443/group/project", "/-"},
		{"http://gitlab.example.test/group/project.git", "http://gitlab.example.test/group/project", "/-"},
	}
	for _, test := range tests {
		t.Run(test.remote, func(t *testing.T) {
			links := parseRepositoryLinks(test.remote)
			require.Equal(t, test.base+test.prefix+"/commit/abc", links.commit("abc"))
			require.Equal(t, test.base+test.prefix+"/compare/abc...def", links.comparison("abc", "def"))
			require.Equal(t, test.base+test.prefix+"/commits/def", links.comparison("", "def"))
		})
	}
	for _, remote := range []string{
		"", "/local/repository", "file:///local/repository", "https://unsupported.test/group/project",
		"https://notgitlab.com/group/project", "https://github.com/only-owner", "https://github.com/owner/project/extra",
		"https://github.com/owner/../project", "https://gitlab.com/group//project", "javascript:alert(1)", "https://%invalid",
	} {
		links := parseRepositoryLinks(remote)
		require.Empty(t, links.commit("abc"), remote)
		require.Empty(t, links.comparison("abc", "def"), remote)
	}
}
