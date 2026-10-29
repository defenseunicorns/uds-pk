// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
)

// Category is a conventional-commit section heading.
type Category string

const (
	BreakingChanges Category = "Breaking Changes"
	Features        Category = "Features"
	BugFixes        Category = "Bug Fixes"
	Performance     Category = "Performance"
	Dependencies    Category = "Dependencies"
	Documentation   Category = "Documentation"
	Maintenance     Category = "Maintenance"
	OtherChanges    Category = "Other Changes"
)

var headerPattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*)(?:\(([^()\r\n]+)\))?(!)?: +([^\s].*)$`)
var footerPattern = regexp.MustCompile(`^([A-Za-z0-9-]+|BREAKING CHANGE)(?:: | #)(.*)$`)

// Message preserves the original subject alongside parsed conventional fields.
// BreakingDescriptions contains footer descriptions, or the header description
// when only a ! marker is present.
type Message struct {
	Subject              string
	Type                 string
	Scope                string
	Description          string
	BreakingDescriptions []string
}

// ParseMessage follows Conventional Commits 1.0.0 without discarding messages
// that use an unrecognized type or do not follow the convention.
func ParseMessage(text string) Message {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	subject := strings.TrimSpace(lines[0])
	message := Message{Subject: subject, Description: subject}
	header := headerPattern.FindStringSubmatch(subject)
	if header != nil {
		message.Type = strings.ToLower(header[1])
		message.Scope = header[2]
		message.Description = strings.TrimSpace(header[4])
	}
	message.BreakingDescriptions = breakingDescriptions(lines[1:])
	if header != nil && header[3] == "!" && len(message.BreakingDescriptions) == 0 {
		message.BreakingDescriptions = []string{message.Description}
	}
	return message
}

func breakingDescriptions(lines []string) []string {
	var descriptions []string
	var current []string
	inFooters, breaking, previousBlank := false, false, false
	flush := func() {
		if description := strings.TrimSpace(strings.Join(current, "\n")); description != "" {
			descriptions = append(descriptions, description)
		}
		current = nil
	}
	for _, line := range lines {
		footer := footerPattern.FindStringSubmatch(line)
		if footer != nil && (inFooters || previousBlank) {
			flush()
			inFooters = true
			breaking = (footer[1] == "BREAKING CHANGE" || footer[1] == "BREAKING-CHANGE") && strings.HasPrefix(line, footer[1]+": ")
			if breaking {
				current = append(current, footer[2])
			}
		} else if breaking {
			current = append(current, line)
		}
		previousBlank = strings.TrimSpace(line) == ""
	}
	flush()
	return descriptions
}

// Category assigns breaking changes first, then dependency scope, then type.
func (message Message) Category() Category {
	if len(message.BreakingDescriptions) > 0 {
		return BreakingChanges
	}
	if strings.EqualFold(message.Scope, "deps") {
		return Dependencies
	}
	switch message.Type {
	case "feat":
		return Features
	case "fix":
		return BugFixes
	case "perf":
		return Performance
	case "docs":
		return Documentation
	case "chore", "build", "ci", "refactor", "test", "style":
		return Maintenance
	default:
		return OtherChanges
	}
}

// Change ties one parsed commit message to its full Git hash.
type Change struct {
	Hash    string
	Message Message
}

// Section groups changes into one non-empty category.
type Section struct {
	Category Category
	Changes  []Change
}

// GroupCommits emits categories in a fixed order, preserving commit order
// within each category and listing each hash once.
func GroupCommits(commits []*object.Commit) []Section {
	groups := make(map[Category][]Change)
	seen := make(map[string]bool)
	for _, commit := range commits {
		hash := commit.Hash.String()
		if seen[hash] {
			continue
		}
		seen[hash] = true
		message := ParseMessage(commit.Message)
		category := message.Category()
		groups[category] = append(groups[category], Change{Hash: hash, Message: message})
	}
	var sections []Section
	for _, category := range []Category{BreakingChanges, Features, BugFixes, Performance, Dependencies, Documentation, Maintenance, OtherChanges} {
		if changes := groups[category]; len(changes) > 0 {
			sections = append(sections, Section{Category: category, Changes: changes})
		}
	}
	return sections
}
