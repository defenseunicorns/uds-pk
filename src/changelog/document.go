// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const changelogHeader = "# Changelog\n\n<!-- uds-pk:generated v1; do not edit -->\n\n"

var generatedReleasePattern = regexp.MustCompile(`(?s)^<!-- uds-pk:release ([0-9a-f]{64}) (\S+) -->\n(.*?)\n<!-- uds-pk:end ([0-9a-f]{64}) -->`)

type generatedRelease struct {
	key      string
	date     time.Time
	markdown string
}

// updateChangelog owns the entire document. It replaces the selected target/tag
// entry and retains other generated releases, ordered by revision date. Existing
// files outside the generated format are rejected without modification.
func updateChangelog(existing []byte, release releaseData, remote string) ([]byte, error) {
	entries, err := readGeneratedChangelog(existing)
	if err != nil {
		return nil, err
	}
	key := releaseKey(release.Target)
	var updated []generatedRelease
	for _, entry := range entries {
		if entry.key != key {
			updated = append(updated, entry)
		}
	}
	updated = append(updated, generatedRelease{key: key, date: release.RevisionDate,
		markdown: fmt.Sprintf("<!-- uds-pk:release %s %s -->\n%s<!-- uds-pk:end %s -->\n",
			key, release.RevisionDate.UTC().Format(time.RFC3339Nano), renderRelease(release, parseRepositoryLinks(remote)), key),
	})
	sort.Slice(updated, func(left, right int) bool {
		if updated[left].date.Equal(updated[right].date) {
			return updated[left].key < updated[right].key
		}
		return updated[left].date.After(updated[right].date)
	})
	var output strings.Builder
	output.WriteString(changelogHeader)
	for _, entry := range updated {
		output.WriteString(entry.markdown)
		output.WriteByte('\n')
	}
	return []byte(output.String()), nil
}

func releaseKey(target releaseTarget) string {
	// A fixed array marshals successfully and avoids ambiguous field separators.
	identity, _ := json.Marshal([]string{target.Kind, target.Name, target.Flavor, target.Tag})
	return fmt.Sprintf("%x", sha256.Sum256(identity))
}

func readGeneratedChangelog(existing []byte) ([]generatedRelease, error) {
	if len(existing) == 0 {
		return nil, nil
	}
	text := strings.ReplaceAll(string(existing), "\r\n", "\n")
	if !strings.HasPrefix(text, changelogHeader) {
		return nil, fmt.Errorf("existing file is not a uds-pk generated changelog; use a new --changelog path and keep handwritten history in a separate file")
	}
	remaining := strings.TrimSpace(strings.TrimPrefix(text, changelogHeader))
	var entries []generatedRelease
	seen := make(map[string]bool)
	for remaining != "" {
		parts := generatedReleasePattern.FindStringSubmatch(remaining)
		if parts == nil || parts[1] != parts[4] || strings.Contains(parts[3], "<!-- uds-pk:") {
			return nil, fmt.Errorf("changelog contains content outside the generated release format or damaged markers")
		}
		if seen[parts[1]] {
			return nil, fmt.Errorf("changelog contains duplicate generated release entries")
		}
		date, err := time.Parse(time.RFC3339Nano, parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid generated release date: %w", err)
		}
		seen[parts[1]] = true
		entries = append(entries, generatedRelease{key: parts[1], date: date, markdown: parts[0] + "\n"})
		remaining = strings.TrimSpace(remaining[len(parts[0]):])
	}
	return entries, nil
}
