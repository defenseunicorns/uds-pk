// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"testing"

	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/stretchr/testify/require"
)

func TestGetPackage(t *testing.T) {
	config := types.ReleaseConfig{Packages: []types.Package{{Name: "package", Path: "package"}}}

	pkg, err := getPackage(config, "package")
	require.NoError(t, err)
	require.Equal(t, "package", pkg.Name)

	_, err = getPackage(config, "missing")
	require.ErrorIs(t, err, ErrPackageNotFound)
}

func TestJoinNonEmpty(t *testing.T) {
	tests := []struct {
		elems []string
		sep   string
		want  string
	}{
		{[]string{"a", "b", "", "c"}, "-", "a-b-c"},
		{[]string{"", "", ""}, ",", ""},
		{[]string{"x"}, "|", "x"},
		{[]string{}, ";", ""},
	}

	for _, tt := range tests {
		got := JoinNonEmpty(tt.sep, tt.elems...)
		if got != tt.want {
			t.Errorf("JoinNonEmpty(%v, %q) = %q; want %q", tt.elems, tt.sep, got, tt.want)
		}
	}
}
