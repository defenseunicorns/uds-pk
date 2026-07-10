// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import "testing"

func TestBuildRepositoryURL(t *testing.T) {
	tests := []struct {
		name            string
		baseRepo        string
		team            string
		flavor          string
		zarfPackageName string
		want            string
	}{
		{
			name:            "non-unicorn without team",
			baseRepo:        "ghcr.io/uds-packages",
			flavor:          "registry1",
			zarfPackageName: "gitlab",
			want:            "ghcr.io/uds-packages/gitlab",
		},
		{
			name:            "non-unicorn with team",
			baseRepo:        "ghcr.io/uds-packages",
			team:            "uds",
			flavor:          "registry1",
			zarfPackageName: "gitlab",
			want:            "ghcr.io/uds-packages/uds/gitlab",
		},
		{
			name:            "unicorn without team",
			baseRepo:        "ghcr.io/uds-packages",
			flavor:          "unicorn",
			zarfPackageName: "gitlab",
			want:            "ghcr.io/uds-packages/private/gitlab",
		},
		{
			name:            "unicorn with team",
			baseRepo:        "ghcr.io/uds-packages",
			team:            "uds",
			flavor:          "unicorn",
			zarfPackageName: "gitlab",
			want:            "ghcr.io/uds-packages/private/uds/gitlab",
		},
		{
			name:            "defenseunicorns org with team",
			baseRepo:        "ghcr.io/defenseunicorns",
			team:            "uds",
			flavor:          "unicorn",
			zarfPackageName: "gitlab",
			want:            "ghcr.io/defenseunicorns/private/uds/gitlab",
		},
		{
			name:            "defenseunicorns org without team",
			baseRepo:        "ghcr.io/defenseunicorns",
			flavor:          "unicorn",
			zarfPackageName: "gitlab",
			want:            "ghcr.io/defenseunicorns/private/gitlab",
		},
		{
			name:            "empty flavor is treated as non-unicorn",
			baseRepo:        "ghcr.io/uds-packages",
			team:            "uds",
			flavor:          "",
			zarfPackageName: "gitlab",
			want:            "ghcr.io/uds-packages/uds/gitlab",
		},
		{
			name:            "scheme is preserved and not collapsed",
			baseRepo:        "https://ghcr.io/uds-packages",
			team:            "uds",
			flavor:          "unicorn",
			zarfPackageName: "gitlab",
			want:            "https://ghcr.io/uds-packages/private/uds/gitlab",
		},
		{
			name:            "trailing slash on base repo is trimmed",
			baseRepo:        "ghcr.io/uds-packages/",
			flavor:          "registry1",
			zarfPackageName: "gitlab",
			want:            "ghcr.io/uds-packages/gitlab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildRepositoryURL(tt.baseRepo, tt.team, tt.flavor, tt.zarfPackageName)
			if err != nil {
				t.Fatalf("buildRepositoryURL returned unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("buildRepositoryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
