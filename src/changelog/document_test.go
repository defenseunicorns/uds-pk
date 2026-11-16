// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateChangelogGeneratedEntry(t *testing.T) {
	release := renderFixture(t)
	generated := requireStableChangelog(t, nil, release)
	require.True(t, bytes.HasPrefix(generated, []byte(changelogHeader)))
	require.Contains(t, string(generated), renderRelease(release, repositoryLinks{}))
	// Regenerating the same target/tag replaces its content exactly once.
	release.Sections = nil
	updated := requireStableChangelog(t, generated, release)
	require.NotEqual(t, generated, updated)
	require.Equal(t, 1, strings.Count(string(updated), "<!-- uds-pk:release "))
	require.Contains(t, string(updated), "No changes matched")
}

func TestUpdateChangelogRetainsGeneratedReleases(t *testing.T) {
	latest := renderFixture(t)
	older, oldest := latest, latest
	older.Target.Tag, oldest.Target.Tag = "api-1.5.0-upstream", "api-1.0.0-upstream"
	older.RevisionDate, oldest.RevisionDate = latest.RevisionDate.Add(-24*time.Hour), latest.RevisionDate.Add(-48*time.Hour)
	var document []byte
	for _, release := range []releaseData{older, oldest, latest} {
		document = requireStableChangelog(t, document, release)
	}
	text := string(document)
	require.Equal(t, 3, strings.Count(text, "<!-- uds-pk:release "))
	require.Less(t, strings.Index(text, "## "+latest.Target.Tag), strings.Index(text, "## "+older.Target.Tag))
	require.Less(t, strings.Index(text, "## "+older.Target.Tag), strings.Index(text, "## "+oldest.Target.Tag))
	older.Sections = nil
	older.RevisionDate = latest.RevisionDate.Add(time.Hour)
	updated := requireStableChangelog(t, document, older)
	require.Less(t, strings.Index(string(updated), "## "+older.Target.Tag), strings.Index(string(updated), "## "+latest.Target.Tag))
	for _, unchanged := range []releaseData{latest, oldest} {
		require.Contains(t, string(updated), renderRelease(unchanged, repositoryLinks{}))
	}
	require.Equal(t, 1, strings.Count(string(updated), "No changes matched"))
}

func TestUpdateChangelogDistinctTargetsAndStableTies(t *testing.T) {
	release := renderFixture(t)
	other := release
	other.Target.Kind, other.Target.Flavor = "bundle", ""
	first := requireStableChangelog(t, nil, release)
	combined := requireStableChangelog(t, first, other)
	otherFirst := requireStableChangelog(t, nil, other)
	reversed := requireStableChangelog(t, otherFirst, release)
	require.Equal(t, combined, reversed)
	require.Equal(t, 2, strings.Count(string(combined), "<!-- uds-pk:release "))
	require.NotEqual(t, releaseKey(release.Target), releaseKey(other.Target))
}

func TestUpdateChangelogRejectsHandwrittenFiles(t *testing.T) {
	for name, content := range map[string]string{
		"plain": "Handwritten release history.\n", "heading": "# Changelog\n\n## 2.0.0\n",
		"frontmatter":   "---\nsidebar_position: 1\n---\n\n# Changelog\n",
		"open fence":    "# Changelog\n\n```text\nExample\n",
		"empty heading": "# Changelog\n\n##\n",
		"old format":    "# Changelog\n\n<!-- uds-pk:release old-format -->\n",
	} {
		t.Run(name, func(t *testing.T) {
			requireChangelogRejected(t, content, "use a new --changelog path")
		})
	}
}

func TestUpdateChangelogRejectsDamagedGeneratedFiles(t *testing.T) {
	release := renderFixture(t)
	valid := requireStableChangelog(t, nil, release)
	key := releaseKey(release.Target)
	begin := fmt.Sprintf("<!-- uds-pk:release %s %s -->\n", key, release.RevisionDate.UTC().Format(time.RFC3339Nano))
	end := "<!-- uds-pk:end " + key + " -->\n"
	for name, body := range map[string]string{
		"unclosed": begin + "content\n", "unmatched end": end,
		"nested":          begin + begin + "content\n" + end + end,
		"mismatched":      begin + "content\n<!-- uds-pk:end " + strings.Repeat("0", 64) + " -->\n",
		"malformed":       "<!-- uds-pk:release invalid -->\n",
		"invalid date":    strings.Replace(begin, release.RevisionDate.UTC().Format(time.RFC3339Nano), "bad-date", 1) + "content\n" + end,
		"duplicate":       strings.TrimPrefix(string(valid), changelogHeader) + begin + "content\n" + end,
		"manual preamble": "Introduction.\n\n" + strings.TrimPrefix(string(valid), changelogHeader),
		"manual suffix":   strings.TrimPrefix(string(valid), changelogHeader) + "Handwritten.\n",
	} {
		t.Run(name, func(t *testing.T) {
			requireChangelogRejected(t, changelogHeader+body, "")
		})
	}
}

func TestUpdateChangelogNormalizesGeneratedLineEndings(t *testing.T) {
	release := renderFixture(t)
	generated := requireStableChangelog(t, nil, release)
	crlf := bytes.ReplaceAll(generated, []byte("\n"), []byte("\r\n"))
	require.Equal(t, generated, requireStableChangelog(t, crlf, release))
}

func requireStableChangelog(t *testing.T, existing []byte, release releaseData) []byte {
	t.Helper()
	updated, err := updateChangelog(existing, release, "")
	require.NoError(t, err)
	repeated, err := updateChangelog(updated, release, "")
	require.NoError(t, err)
	require.Equal(t, updated, repeated)
	return updated
}

func requireChangelogRejected(t *testing.T, content, message string) {
	t.Helper()
	existing := []byte(content)
	for range 2 {
		updated, err := updateChangelog(existing, renderFixture(t), "")
		require.ErrorContains(t, err, message)
		require.Nil(t, updated)
		require.Equal(t, content, string(existing))
	}
}
