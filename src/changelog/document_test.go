// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateChangelogPreservesManualContent(t *testing.T) {
	release := renderFixture(t)
	existing, err := os.ReadFile("testdata/manual-changelog.md")
	require.NoError(t, err)
	updated, err := UpdateChangelog(existing, release, "https://github.com/example/project")
	require.NoError(t, err)
	blocks, err := readBlocks(contentLines(string(updated)))
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	block := blocks[0]
	// Removing the generated block restores every byte of the original file,
	// including the fenced marker example and the handwritten release.
	restored := append(append([]byte(nil), updated[:block.start]...), updated[block.end+1:]...)
	require.Equal(t, existing, restored)
	require.Contains(t, string(updated), "<!-- uds-pk:release "+releaseKey(release.Target))

	repeated, err := UpdateChangelog(updated, release, "https://github.com/example/project")
	require.NoError(t, err)
	require.Equal(t, updated, repeated)

	// Regeneration replaces edits inside this block without touching its neighbors.
	edited := bytes.Replace(updated, []byte("replace the old request format"), []byte("Hand-edited generated text"), 1)
	regenerated, err := UpdateChangelog(edited, release, "https://github.com/example/project")
	require.NoError(t, err)
	require.Equal(t, updated, regenerated)
}

func TestUpdateChangelogMultipleReleases(t *testing.T) {
	latest := renderFixture(t)
	older := latest
	older.Target.Tag = "api-1.5.0-upstream"
	older.RevisionDate = latest.RevisionDate.Add(-24 * time.Hour)
	oldest := latest
	oldest.Target.Tag = "api-1.0.0-upstream"
	oldest.RevisionDate = latest.RevisionDate.Add(-48 * time.Hour)
	var changelog []byte
	for _, release := range []Release{older, oldest, latest} {
		updated, err := UpdateChangelog(changelog, release, "")
		require.NoError(t, err)
		changelog = updated
	}
	require.True(t, bytes.HasPrefix(changelog, []byte("# Changelog\n\n")))
	blocks, err := readBlocks(contentLines(string(changelog)))
	require.NoError(t, err)
	require.Len(t, blocks, 3)
	require.Equal(t, []string{releaseKey(latest.Target), releaseKey(older.Target), releaseKey(oldest.Target)}, []string{blocks[0].key, blocks[1].key, blocks[2].key})

	// Refreshing a section leaves the surrounding sections byte-for-byte intact.
	prefix := append([]byte(nil), changelog[:blocks[1].start]...)
	suffix := append([]byte(nil), changelog[blocks[1].end:]...)
	older.Sections = nil
	updated, err := UpdateChangelog(changelog, older, "")
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(updated, prefix))
	require.True(t, bytes.HasSuffix(updated, suffix))
	require.Equal(t, 1, strings.Count(string(updated), "No changes matched"))
}

func TestUpdateChangelogDistinctTargetIdentities(t *testing.T) {
	release := renderFixture(t)
	other := release
	other.Target.Kind = "bundle"
	other.Target.Flavor = ""
	// Even the same formatted tag can have distinct package/bundle owners.
	first, err := UpdateChangelog(nil, release, "")
	require.NoError(t, err)
	combined, err := UpdateChangelog(first, other, "")
	require.NoError(t, err)
	blocks, err := readBlocks(contentLines(string(combined)))
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	require.NotEqual(t, blocks[0].key, blocks[1].key)
	// Equal revision dates use identity as a stable tie-breaker.
	otherFirst, err := UpdateChangelog(nil, other, "")
	require.NoError(t, err)
	reversed, err := UpdateChangelog(otherFirst, release, "")
	require.NoError(t, err)
	require.Equal(t, combined, reversed)
}

func TestUpdateChangelogLineEndingsAndPreambles(t *testing.T) {
	release := renderFixture(t)
	for _, preamble := range []string{"# Custom history", "# Custom history\n", "# Custom history\n\nIntroduction\n\n"} {
		updated, err := UpdateChangelog([]byte(preamble), release, "")
		require.NoError(t, err)
		require.True(t, bytes.HasPrefix(updated, []byte(preamble)))
		require.NotContains(t, string(updated), "# Changelog")
	}
	existing := []byte("# Changelog\r\n\r\nIntroduction\r\n\r\n## previous\r\n\r\nHandwritten.\r\n")
	updated, err := UpdateChangelog(existing, release, "")
	require.NoError(t, err)
	require.NotContains(t, strings.ReplaceAll(string(updated), "\r\n", ""), "\n")
	require.True(t, bytes.HasSuffix(updated, []byte("## previous\r\n\r\nHandwritten.\r\n")))
	repeated, err := UpdateChangelog(updated, release, "")
	require.NoError(t, err)
	require.Equal(t, updated, repeated)
}

func TestUpdateChangelogManualConflicts(t *testing.T) {
	release := renderFixture(t)
	for _, heading := range []string{
		"## " + release.Target.Tag,
		"## " + release.Target.Tag + " (2026-10-29)",
		"## [" + release.Target.Tag + "](https://example.test/compare) (2026-10-29)",
		"## `" + release.Target.Tag + "`",
		"  ## " + release.Target.Tag + " ##",
	} {
		updated, err := UpdateChangelog([]byte("# Changelog\n\n"+heading+"\n\nHandwritten.\n"), release, "")
		require.ErrorContains(t, err, "handwritten section")
		require.Nil(t, updated)
	}
	// A longer tag sharing the same prefix is a different release.
	_, err := UpdateChangelog([]byte("## "+release.Target.Tag+"-extra\n"), release, "")
	require.NoError(t, err)
}

func TestUpdateChangelogInvalidMarkers(t *testing.T) {
	release := renderFixture(t)
	valid, err := UpdateChangelog(nil, release, "")
	require.NoError(t, err)
	key := releaseKey(release.Target)
	begin := fmt.Sprintf("<!-- uds-pk:release %s %s -->\n", key, release.RevisionDate.UTC().Format(time.RFC3339Nano))
	end := "<!-- uds-pk:end " + key + " -->\n"
	for name, text := range map[string]string{
		"unclosed":      begin + "content\n",
		"unmatched end": end,
		"nested":        begin + begin + end,
		"duplicate":     string(valid) + begin + end,
		"mismatched":    begin + "<!-- uds-pk:end " + strings.Repeat("0", 64) + " -->\n",
		"malformed":     "<!-- uds-pk:release invalid -->\n",
		"invalid date":  strings.Replace(begin, release.RevisionDate.UTC().Format(time.RFC3339Nano), "bad-date", 1) + end,
	} {
		t.Run(name, func(t *testing.T) {
			updated, err := UpdateChangelog([]byte(text), release, "")
			require.Error(t, err)
			require.Nil(t, updated)
		})
	}
}
