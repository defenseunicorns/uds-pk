// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var releaseMarker = regexp.MustCompile(`^<!-- uds-pk:release ([0-9a-f]{64}) (\S+) -->$`)
var endMarker = regexp.MustCompile(`^<!-- uds-pk:end ([0-9a-f]{64}) -->$`)
var sectionHeading = regexp.MustCompile(`^ {0,3}##[\t ]+(.+?)(?:[\t ]+#+)?[\t ]*$`)
var codeFence = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})(.*)$")

type generatedBlock struct {
	key        string
	date       time.Time
	start, end int
}

type documentLine struct {
	text       string
	start, end int
}

// UpdateChangelog inserts a generated release section or replaces the section
// with the same target identity and tag. Text outside generated blocks is kept
// byte-for-byte. New sections are inserted by revision date, newest first.
func UpdateChangelog(existing []byte, release Release, remote string) ([]byte, error) {
	text := string(existing)
	lines := contentLines(text)
	blocks, err := readBlocks(lines)
	if err != nil {
		return nil, err
	}
	if err := checkManualConflict(lines, blocks, release.Target.Tag); err != nil {
		return nil, err
	}
	newline := "\n"
	if strings.Contains(text, "\r\n") {
		newline = "\r\n"
	}
	key := releaseKey(release.Target)
	block := fmt.Sprintf("<!-- uds-pk:release %s %s -->\n%s<!-- uds-pk:end %s -->\n",
		key, release.RevisionDate.UTC().Format(time.RFC3339Nano), renderRelease(release, parseRepositoryLinks(remote)), key)
	block = strings.ReplaceAll(block, "\n", newline)
	for _, previous := range blocks {
		if previous.key == key {
			return []byte(text[:previous.start] + block + text[previous.end:]), nil
		}
	}
	if len(existing) == 0 {
		return []byte("# Changelog" + newline + newline + block), nil
	}
	position := insertionPosition(lines, blocks, release.RevisionDate, key, len(text))
	prefix, suffix := text[:position], text[position:]
	separator := ""
	if prefix != "" && !strings.HasSuffix(prefix, newline+newline) {
		separator = newline
		if !strings.HasSuffix(prefix, newline) {
			separator += newline
		}
	}
	ending := ""
	if suffix != "" && !strings.HasPrefix(suffix, newline) {
		ending = newline
	}
	return []byte(prefix + separator + block + ending + suffix), nil
}

func releaseKey(target Target) string {
	// A fixed string array always marshals successfully. JSON avoids ambiguous
	// identities when names, flavors, and tags themselves contain separators.
	identity, _ := json.Marshal([]string{target.Kind, target.Name, target.Flavor, target.Tag})
	return fmt.Sprintf("%x", sha256.Sum256(identity))
}

func readBlocks(lines []documentLine) ([]generatedBlock, error) {
	var blocks []generatedBlock
	var open *generatedBlock
	seen := make(map[string]bool)
	for _, line := range lines {
		if !strings.Contains(line.text, "<!-- uds-pk:") {
			continue
		}
		if marker := releaseMarker.FindStringSubmatch(line.text); marker != nil {
			if open != nil || seen[marker[1]] {
				return nil, fmt.Errorf("changelog contains nested or duplicate generated release markers")
			}
			date, err := time.Parse(time.RFC3339Nano, marker[2])
			if err != nil {
				return nil, fmt.Errorf("invalid generated release date: %w", err)
			}
			open = &generatedBlock{key: marker[1], date: date, start: line.start}
			seen[open.key] = true
		} else if marker := endMarker.FindStringSubmatch(line.text); marker != nil {
			if open == nil || marker[1] != open.key {
				return nil, fmt.Errorf("changelog contains an unmatched generated release end marker")
			}
			open.end = line.end
			blocks = append(blocks, *open)
			open = nil
		} else {
			return nil, fmt.Errorf("changelog contains a malformed generated release marker")
		}
	}
	if open != nil {
		return nil, fmt.Errorf("changelog contains an unclosed generated release marker")
	}
	return blocks, nil
}

func checkManualConflict(lines []documentLine, blocks []generatedBlock, tag string) error {
	for _, line := range lines {
		heading := sectionHeading.FindStringSubmatch(line.text)
		if heading == nil || insideBlock(line.start, blocks) {
			continue
		}
		for _, label := range []string{tag, markdownInline(tag), "`" + tag + "`"} {
			if heading[1] == label || strings.HasPrefix(heading[1], label+" (") || strings.HasPrefix(heading[1], "["+label+"](") {
				return fmt.Errorf("changelog already has a handwritten section for tag %q; review it before generating this release", tag)
			}
		}
	}
	return nil
}

func insideBlock(position int, blocks []generatedBlock) bool {
	for _, block := range blocks {
		if position >= block.start && position < block.end {
			return true
		}
	}
	return false
}

func insertionPosition(lines []documentLine, blocks []generatedBlock, date time.Time, key string, fallback int) int {
	if len(blocks) > 0 {
		for _, block := range blocks {
			if date.After(block.date) || (date.Equal(block.date) && key < block.key) {
				return block.start
			}
		}
		return blocks[len(blocks)-1].end
	}
	for _, line := range lines {
		if sectionHeading.MatchString(line.text) {
			return line.start
		}
	}
	return fallback
}

// Only structural lines outside fenced code are inspected. Offsets refer to the
// original bytes, including CRLFs, so author-written content need not be parsed
// and reserialized just to update a generated section.
func contentLines(text string) []documentLine {
	var lines []documentLine
	var fenceByte byte
	fenceLength, position := 0, 0
	for _, chunk := range strings.SplitAfter(text, "\n") {
		line := strings.TrimSuffix(strings.TrimSuffix(chunk, "\n"), "\r")
		start := position
		position += len(chunk)
		if fence := codeFence.FindStringSubmatch(line); fence != nil {
			if fenceByte == 0 {
				fenceByte, fenceLength = fence[1][0], len(fence[1])
			} else if fence[1][0] == fenceByte && len(fence[1]) >= fenceLength && strings.TrimSpace(fence[2]) == "" {
				fenceByte = 0
			}
			continue
		}
		if fenceByte == 0 {
			lines = append(lines, documentLine{text: line, start: start, end: position})
		}
	}
	return lines
}
