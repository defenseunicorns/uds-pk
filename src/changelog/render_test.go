// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseunicorns/uds-pk/src/test"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func renderFixture(t *testing.T) releaseData {
	t.Helper()
	var fixture struct {
		Target       releaseTarget
		From         string
		To           string
		RevisionDate string `yaml:"revisionDate"`
		Commits      []struct{ Hash, Message string }
	}
	require.NoError(t, utils.LoadYaml("testdata/render.yaml", &fixture))
	date, err := time.Parse(time.RFC3339, fixture.RevisionDate)
	require.NoError(t, err)
	var commits []*object.Commit
	for _, commit := range fixture.Commits {
		commits = append(commits, &object.Commit{Hash: plumbing.NewHash(commit.Hash), Message: commit.Message})
	}
	return releaseData{Target: fixture.Target, From: fixture.From, To: fixture.To, RevisionDate: date, Sections: groupCommits(commits)}
}

func TestRenderNotesGolden(t *testing.T) {
	release := renderFixture(t)
	expected := test.ReadFile(t, "testdata/notes.golden.md")
	actual := renderNotes(release, "git@github.com:example/project.git")
	require.Equal(t, string(expected), string(actual))
	require.Equal(t, actual, renderNotes(release, "https://username:secret@github.com/example/project.git?token=secret#secret"))
}

func TestRenderNotesInitialAndEmpty(t *testing.T) {
	release := renderFixture(t)
	release.From = ""
	release.Target = releaseTarget{Kind: "bundle", Name: "platform", Version: "testing", Tag: "platform-testing"}
	release.Sections = nil
	notes := string(renderNotes(release, "ssh://git@gitlab.example.test/group/subgroup/project.git"))
	require.Contains(t, notes, "- **Target:** bundle platform\n")
	require.Contains(t, notes, "Initial release (all reachable history)")
	require.Contains(t, notes, "[Commit history](https://gitlab.example.test/group/subgroup/project/-/commits/"+release.To+")")
	require.Contains(t, notes, "No changes matched the selected target and revision range.")
	require.NotContains(t, notes, "### ")
	require.NotContains(t, notes, "/compare/")
	require.NotContains(t, notes, "flavor:")
}

func TestRenderNotesUnknownRemote(t *testing.T) {
	release := renderFixture(t)
	notes := string(renderNotes(release, "https://user:secret@unsupported.test/project?token=secret"))
	require.Contains(t, notes, "Web links omitted: origin is missing or unsupported.")
	require.Contains(t, notes, "- **Revision:** "+release.To+"\n")
	require.Contains(t, notes, "(bbbbbbb)")
	require.NotContains(t, notes, "secret")
	require.NotContains(t, notes, "unsupported.test")
}

func TestRenderNotesEscapesText(t *testing.T) {
	release := renderFixture(t)
	release.Target.Tag = "tag\n\n# injected heading"
	release.Sections = []section{
		{Category: features, Changes: []change{{Hash: "abc", Message: parseMessage("feat!: remove the old endpoint")}}},
		{Category: otherChanges, Changes: []change{{Hash: "def", Message: parseMessage("")}}},
		{Category: documentation},
	}
	notes := string(renderNotes(release, ""))
	require.Contains(t, notes, "## tag \\# injected heading\n")
	require.NotContains(t, notes, "\n# injected heading")
	require.Equal(t, 1, strings.Count(notes, "remove the old endpoint"))
	require.Contains(t, notes, "\\(empty commit message\\)")
	require.NotContains(t, notes, "### Documentation")
}

func TestRenderNotesKeepsLiteralBlockSyntax(t *testing.T) {
	release := renderFixture(t)
	var changes []change
	for _, subject := range []string{"- literal bullet", "+ literal bullet", "1. literal item", "123456789. literal item", "1) literal item", "---", "---- ----", "==="} {
		changes = append(changes, change{Hash: "abc", Message: parseMessage(subject)})
	}
	release.Sections = []section{
		{Category: breakingChanges, Changes: []change{{Hash: "def", Message: parseMessage("fix: preserve literal breaking details\n\nBREAKING CHANGE: first line\n---\n\n1. literal item\n+ literal bullet\n===\n- - -")}}},
		{Category: otherChanges, Changes: changes},
	}
	expected := test.ReadFile(t, "testdata/notes-literal-blocks.golden.md")
	require.Equal(t, string(expected), string(renderNotes(release, "")))
}
