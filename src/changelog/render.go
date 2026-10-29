// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"fmt"
	"html"
	"strings"
	"time"
)

// Release is the common model for standalone notes and a changelog section.
// From and To are resolved commit hashes; an empty From is an initial release.
type Release struct {
	Target       Target
	From         string
	To           string
	RevisionDate time.Time
	Sections     []Section
}

// RenderNotes generates a standalone Markdown document without hosted API calls.
// Unsupported or absent remotes produce plain commit references instead of URLs.
func RenderNotes(release Release, remote string) []byte {
	return []byte("# Release notes\n\n" + renderRelease(release, parseRepositoryLinks(remote)))
}

func renderRelease(release Release, links repositoryLinks) string {
	var output strings.Builder
	fmt.Fprintf(&output, "## %s\n\n", markdownInline(release.Target.Tag))
	target := release.Target.Kind
	if release.Target.Name != "" {
		target += " " + release.Target.Name
	}
	if release.Target.Flavor != "" {
		target += " (flavor: " + release.Target.Flavor + ")"
	}
	fmt.Fprintf(&output, "- **Target:** %s\n", markdownInline(target))
	fmt.Fprintf(&output, "- **Version:** %s\n", markdownInline(release.Target.Version))
	fmt.Fprintf(&output, "- **Revision date (UTC):** %s\n", release.RevisionDate.UTC().Format("2006-01-02"))
	fmt.Fprintf(&output, "- **Revision:** %s\n", markdownLink(release.To, links.commit(release.To)))
	baseline := "Initial release (all reachable history)"
	if release.From != "" {
		baseline = markdownLink(release.From, links.commit(release.From))
	}
	fmt.Fprintf(&output, "- **Baseline:** %s\n\n", baseline)
	if comparison := links.comparison(release.From, release.To); comparison != "" {
		label := "Full changelog"
		if release.From == "" {
			label = "Commit history"
		}
		output.WriteString(markdownLink(label, comparison) + "\n\n")
	} else {
		output.WriteString("Web links omitted: origin is missing or unsupported.\n\n")
	}
	count := 0
	for _, section := range release.Sections {
		if len(section.Changes) == 0 {
			continue
		}
		fmt.Fprintf(&output, "### %s\n\n", markdownInline(string(section.Category)))
		for _, change := range section.Changes {
			renderChange(&output, change, links)
			count++
		}
		output.WriteString("\n")
	}
	if count == 0 {
		output.WriteString("No changes matched the selected target and revision range.\n")
	}
	return strings.TrimRight(output.String(), "\n") + "\n"
}

func renderChange(output *strings.Builder, change Change, links repositoryLinks) {
	message := change.Message
	label := message.Type
	if message.Scope != "" {
		label += "(" + message.Scope + ")"
	}
	output.WriteString("- ")
	if label != "" {
		fmt.Fprintf(output, "**%s:** ", markdownInline(label))
	}
	description := message.Description
	if description == "" {
		description = "(empty commit message)"
	}
	hash := change.Hash
	if len(hash) > 7 {
		hash = hash[:7]
	}
	fmt.Fprintf(output, "%s (%s)\n", markdownInline(description), markdownLink(hash, links.commit(change.Hash)))
	for _, breaking := range message.BreakingDescriptions {
		// A !-only commit already describes its breaking change in the bullet.
		if breaking == message.Description {
			continue
		}
		output.WriteString("\n  **Breaking change:** ")
		for index, line := range strings.Split(breaking, "\n") {
			if index > 0 {
				output.WriteString("\n")
				if strings.TrimSpace(line) != "" {
					output.WriteString("  ")
				}
			}
			output.WriteString(markdownInline(line))
		}
		output.WriteString("\n")
	}
}

func markdownInline(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	text = strings.NewReplacer(
		`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`,
		"[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`,
		"#", `\#`, "!", `\!`, "|", `\|`, "~", `\~`,
	).Replace(text)
	return html.EscapeString(text)
}

func markdownLink(label, address string) string {
	if address == "" {
		return markdownInline(label)
	}
	// Parentheses delimit Markdown destinations even when valid in URL paths.
	address = strings.NewReplacer("(", "%28", ")", "%29").Replace(address)
	return "[" + markdownInline(label) + "](" + address + ")"
}
