// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	markdowntext "github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var releaseMarker = regexp.MustCompile(`^<!-- uds-pk:release ([0-9a-f]{64}) (\S+) -->$`)
var endMarker = regexp.MustCompile(`^<!-- uds-pk:end ([0-9a-f]{64}) -->$`)

type generatedBlock struct {
	key        string
	date       time.Time
	start, end int
}

type documentLine struct {
	headingLevel int
	text         string
	start, end   int
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
			return finishChangelogUpdate(text[:previous.start]+block+text[previous.end:], key)
		}
	}
	if len(existing) == 0 {
		return finishChangelogUpdate("# Changelog"+newline+newline+block, key)
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
	return finishChangelogUpdate(prefix+separator+block+ending+suffix, key)
}

// Verify the resulting Markdown exposes the generated markers. In particular,
// an append after an open fence would hide the section and make later runs add
// duplicates. Validate before returning any content for the caller to write.
func finishChangelogUpdate(text, key string) ([]byte, error) {
	blocks, err := readBlocks(contentLines(text))
	if err != nil {
		return nil, err
	}
	for _, block := range blocks {
		if block.key == key {
			return []byte(text), nil
		}
	}
	return nil, fmt.Errorf("generated release section would be hidden by surrounding Markdown; close any open code fence or HTML block before updating the changelog")
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
		if line.headingLevel != 0 {
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
		if line.headingLevel == 0 || insideBlock(line.start, blocks) {
			continue
		}
		if headingHasReleaseLabel(line.text, tag) {
			return fmt.Errorf("changelog already has a handwritten section for tag %q; review it before generating this release", tag)
		}
	}
	return nil
}

func headingHasReleaseLabel(heading, label string) bool {
	// A release label can stand alone or precede a date/subtitle. Match a
	// whitespace boundary so similarly prefixed tags remain distinct.
	if heading == label || strings.HasPrefix(heading, label+" ") || strings.HasPrefix(heading, label+"\t") {
		return true
	}
	linked := "[" + label + "]"
	if !strings.HasPrefix(heading, linked) {
		return false
	}
	suffix := strings.TrimPrefix(heading, linked)
	// Support inline links, full/collapsed references, and shortcut references.
	// Reference definitions do not need to be rewritten or resolved to detect
	// that the heading already names this release.
	return suffix == "" || strings.HasPrefix(suffix, "(") || strings.HasPrefix(suffix, "[") || strings.HasPrefix(suffix, " ") || strings.HasPrefix(suffix, "\t")
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
	firstHeading := true
	for _, line := range lines {
		if line.headingLevel == 0 {
			continue
		}
		// Preserve an initial level-one document title and its preamble.
		if line.headingLevel != 1 || !firstHeading {
			return line.start
		}
		firstHeading = false
	}
	return fallback
}

// Parse structure without reserializing Markdown. Only top-level headings and
// reserved HTML comment blocks can affect release sections; code, quotes, lists,
// and inline marker examples remain ordinary author-written content. Positions
// are offsets into the original bytes, including CRLF line endings.
func contentLines(text string) []documentLine {
	offset := frontmatterEnd(text)
	source := []byte(text[offset:])
	document := goldmark.New().Parser().Parse(markdowntext.NewReader(source))
	var lines []documentLine
	for node := document.FirstChild(); node != nil; node = node.NextSibling() {
		switch node := node.(type) {
		case *ast.Heading:
			if node.Lines().Len() == 0 {
				continue
			}
			position := offset + node.Lines().At(0).Start
			start := strings.LastIndexByte(text[:position], '\n') + 1
			lines = append(lines, documentLine{text: headingText(node, source), start: start, headingLevel: node.Level})
		case *ast.HTMLBlock:
			if node.HTMLBlockType != ast.HTMLBlockType2 || node.Lines().Len() == 0 {
				continue
			}
			segment := node.Lines().At(0)
			line := strings.TrimSpace(string(segment.Value(source)))
			if !strings.HasPrefix(line, "<!-- uds-pk:") {
				continue
			}
			start := strings.LastIndexByte(text[:offset+segment.Start], '\n') + 1
			lines = append(lines, documentLine{text: line, start: start, end: offset + segment.Stop})
		}
	}
	return lines
}

// Leading YAML frontmatter is opaque metadata, not Markdown. Recognize only a
// complete delimited block; a lone opening thematic break remains Markdown.
// Keep its original bytes and translate body offsets back into the whole file.
func frontmatterEnd(text string) int {
	first, remaining, found := strings.Cut(text, "\n")
	if !found || strings.TrimRight(strings.TrimPrefix(first, "\ufeff"), " \t\r") != "---" {
		return 0
	}
	offset := len(text) - len(remaining)
	for remaining != "" {
		line, rest, _ := strings.Cut(remaining, "\n")
		offset += len(remaining) - len(rest)
		delimiter := strings.TrimRight(line, " \t\r")
		if delimiter == "---" || delimiter == "..." {
			return offset
		}
		remaining = rest
	}
	return 0
}

// Read visible heading labels through links, emphasis, code spans, and escaped
// punctuation. Unresolved reference labels keep their literal brackets, which
// headingHasReleaseLabel also recognizes.
func headingText(heading *ast.Heading, source []byte) string {
	var label strings.Builder
	_ = ast.Walk(heading, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch node := node.(type) {
		case *ast.Text:
			value := node.Segment.Value(source)
			if _, code := node.Parent().(*ast.CodeSpan); !code {
				value = []byte(html.UnescapeString(string(util.UnescapePunctuations(value))))
			}
			label.Write(value)
			if node.SoftLineBreak() || node.HardLineBreak() {
				label.WriteByte(' ')
			}
		case *ast.String:
			label.Write(node.Value)
		}
		return ast.WalkContinue, nil
	})
	return strings.Join(strings.Fields(label.String()), " ")
}
