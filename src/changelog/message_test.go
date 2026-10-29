// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func TestParseMessage(t *testing.T) {
	var fixtures []struct {
		Name        string
		Text        string
		Type        string
		Scope       string
		Description string
		Breaking    []string
		Category    Category
	}
	require.NoError(t, utils.LoadYaml("testdata/messages.yaml", &fixtures))
	require.NotEmpty(t, fixtures)
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			message := ParseMessage(fixture.Text)
			require.Equal(t, Message{
				Subject:              strings.TrimSpace(strings.Split(fixture.Text, "\n")[0]),
				Type:                 fixture.Type,
				Scope:                fixture.Scope,
				Description:          fixture.Description,
				BreakingDescriptions: fixture.Breaking,
			}, message)
			require.Equal(t, fixture.Category, message.Category())
		})
	}
}

func TestMaintenanceTypes(t *testing.T) {
	for _, commitType := range []string{"chore", "build", "ci", "refactor", "test", "style"} {
		require.Equal(t, Maintenance, ParseMessage(commitType+": maintain the project").Category())
	}
}

func TestGroupCommits(t *testing.T) {
	fixture := newHistoryFixture(t)
	history, err := ReadHistory(t.Context(), fixture.directory, RevisionRange{Initial: true})
	require.NoError(t, err)
	selected, err := FilterCommits(t.Context(), history, fixture.directory, Target{}, nil)
	require.NoError(t, err)
	// Deliberately repeat a commit to verify one entry per hash.
	commits := append(append([]*object.Commit(nil), selected...), selected[0])
	sections := GroupCommits(commits)
	var categories []Category
	var hashes []string
	for _, section := range sections {
		categories = append(categories, section.Category)
		require.NotEmpty(t, section.Changes)
		for _, change := range section.Changes {
			hashes = append(hashes, change.Hash)
		}
	}
	require.Equal(t, []Category{Features, BugFixes, Dependencies, Maintenance}, categories)
	require.ElementsMatch(t, commitHashes(History{Commits: selected}), hashes)
	require.Equal(t, fixture.hashes["base"].String(), sections[0].Changes[0].Hash)
	require.Equal(t, fixture.hashes["feature"].String(), sections[0].Changes[1].Hash)
	require.Empty(t, GroupCommits(nil))
}

func TestGroupCommitsCategoryOrder(t *testing.T) {
	var commits []*object.Commit
	for index, subject := range []string{
		"A nonconventional message", "chore: maintenance", "docs: documentation", "chore(deps): dependencies",
		"perf: performance", "fix: bug fix", "feat: feature", "fix!: breaking change",
	} {
		commits = append(commits, &object.Commit{Hash: plumbing.ComputeHash(plumbing.CommitObject, []byte{byte(index)}), Message: subject})
	}
	var categories []Category
	for _, section := range GroupCommits(commits) {
		categories = append(categories, section.Category)
	}
	require.Equal(t, []Category{BreakingChanges, Features, BugFixes, Performance, Dependencies, Documentation, Maintenance, OtherChanges}, categories)
}
