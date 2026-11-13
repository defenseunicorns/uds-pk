// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
)

// changeCategory is a conventional-commit section heading.
type changeCategory string

const (
	breakingChanges changeCategory = "Breaking Changes"
	features        changeCategory = "Features"
	bugFixes        changeCategory = "Bug Fixes"
	performance     changeCategory = "Performance"
	dependencies    changeCategory = "Dependencies"
	documentation   changeCategory = "Documentation"
	maintenance     changeCategory = "Maintenance"
	otherChanges    changeCategory = "Other Changes"
)

var headerPattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*)(?:\(([^()\r\n]+)\))?(!)?: +([^\s].*)$`)
var footerPattern = regexp.MustCompile(`^([A-Za-z0-9-]+|BREAKING CHANGE)(?:: | #)(.*)$`)

// commitMessage preserves the original subject alongside parsed conventional fields.
// BreakingDescriptions contains footer descriptions, or the header description
// when only a ! marker is present.
type commitMessage struct {
	Subject              string
	Type                 string
	Scope                string
	Description          string
	BreakingDescriptions []string
}

// parseMessage follows Conventional Commits 1.0.0 without discarding messages
// that use an unrecognized type or do not follow the convention.
func parseMessage(text string) commitMessage {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	subject := strings.TrimSpace(lines[0])
	message := commitMessage{Subject: subject, Description: subject}
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

// category assigns breaking changes first, then dependency scope, then type.
func (message commitMessage) category() changeCategory {
	if len(message.BreakingDescriptions) > 0 {
		return breakingChanges
	}
	if strings.EqualFold(message.Scope, "deps") {
		return dependencies
	}
	switch message.Type {
	case "feat":
		return features
	case "fix":
		return bugFixes
	case "perf":
		return performance
	case "docs":
		return documentation
	case "chore", "build", "ci", "refactor", "test", "style":
		return maintenance
	default:
		return otherChanges
	}
}

// change ties one parsed commit message to its full Git hash.
type change struct {
	Hash    string
	Message commitMessage
}

// section groups changes into one non-empty category.
type section struct {
	Category changeCategory
	Changes  []change
}

// groupCommits emits categories in a fixed order, preserving commit order
// within each category. Input commits come from the unique history traversal.
func groupCommits(commits []*object.Commit) []section {
	groups := make(map[changeCategory][]change)
	for _, commit := range commits {
		hash := commit.Hash.String()
		message := parseMessage(commit.Message)
		category := message.category()
		groups[category] = append(groups[category], change{Hash: hash, Message: message})
	}
	var sections []section
	for _, category := range []changeCategory{breakingChanges, features, bugFixes, performance, dependencies, documentation, maintenance, otherChanges} {
		if changes := groups[category]; len(changes) > 0 {
			sections = append(sections, section{Category: category, Changes: changes})
		}
	}
	return sections
}
