// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/test"
	"github.com/defenseunicorns/uds-pk/src/types"
	goyaml "github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
)

func TestGeneratePreparesArtifactsWithoutWriting(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	path := filepath.Join(fixture.Directory, "CHANGELOG.md")
	existing := requireStableChangelog(t, nil, releaseData{Target: releaseTarget{Kind: "package", Name: "api", Tag: "api-1.0.0"}})
	require.NoError(t, os.WriteFile(path, existing, 0o644))
	generated, err := Generate(t.Context(), GenerateOptions{
		Directory: fixture.Directory, Selection: Selection{Package: "api", Flavor: "upstream"},
		Revisions: RevisionRange{From: "previous-api"}, Output: "notes/api.md", Changelog: path,
	})
	require.NoError(t, err)
	require.Contains(t, string(generated.Notes), "## api-2.0.0-upstream\n")
	require.Contains(t, string(generated.Notes), "configure API replicas")
	require.Contains(t, string(generated.Notes), "/compare/"+fixture.Base+"..."+fixture.Head)
	require.NotContains(t, string(generated.Notes), "retry failed jobs")
	require.NotContains(t, string(generated.Notes), "fixture-token")
	require.Len(t, generated.Artifacts, 2)
	require.Equal(t, filepath.Join(fixture.Directory, "notes/api.md"), generated.Artifacts[0].Path)
	require.Equal(t, generated.Notes, generated.Artifacts[0].Content)
	require.Equal(t, path, generated.Artifacts[1].Path)
	require.Contains(t, string(generated.Artifacts[1].Content), "<!-- uds-pk:release ")
	require.Contains(t, string(generated.Artifacts[1].Content), "## api-1.0.0\n")
	require.Equal(t, existing, test.ReadFile(t, path))
	_, err = os.Stat(filepath.Join(fixture.Directory, "notes"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestGenerateBundleOnlyInitialEndpoint(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	config := types.ReleaseConfig{Bundles: []types.Bundle{{Name: "platform", Path: "bundles/platform", Version: "testing"}}}
	data, err := goyaml.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(fixture.Directory, "releaser.yaml"), data, 0o644))
	generated, err := Generate(t.Context(), GenerateOptions{
		Directory: fixture.Directory, Selection: Selection{Bundle: "platform"},
		Revisions: RevisionRange{Initial: true, To: fixture.Base},
	})
	require.NoError(t, err)
	require.Contains(t, string(generated.Notes), "## platform-testing\n")
	require.Contains(t, string(generated.Notes), "Initial release (all reachable history)")
	require.Contains(t, string(generated.Notes), "initial fixture")
	require.NotContains(t, string(generated.Notes), "refresh platform references")
	require.Empty(t, generated.Artifacts)
}

func TestGenerateNestedDirectorySymlink(t *testing.T) {
	fixture := test.CreateNotesFixture(t)
	options := GenerateOptions{
		Directory: fixture.Directory, Selection: Selection{Package: "api", Flavor: "upstream"},
		Revisions: RevisionRange{From: "previous-api"}, IncludePaths: []string{"shared"},
	}
	physical, err := Generate(t.Context(), options)
	require.NoError(t, err)
	link := filepath.Join(t.TempDir(), "release")
	require.NoError(t, os.Symlink(fixture.Directory, link))
	options.Directory = link
	linked, err := Generate(t.Context(), options)
	require.NoError(t, err)
	require.Equal(t, physical, linked)
}
