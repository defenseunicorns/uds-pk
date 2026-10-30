// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"net/url"
	"strings"
)

type repositoryLinks struct {
	base   string
	gitlab bool
}

// Recognize common hosted remotes without echoing credentials or unrecognized
// origin strings. All link suffixes use resolved object IDs rather than tags.
func parseRepositoryLinks(remote string) repositoryLinks {
	if !strings.Contains(remote, "://") {
		// SCP-style SSH URLs, for example git@github.com:owner/repository.git.
		prefix, path, found := strings.Cut(remote, ":")
		if !found || strings.Contains(prefix, "/") {
			return repositoryLinks{}
		}
		remote = "ssh://" + prefix + "/" + path
	}
	parsed, err := url.Parse(remote)
	if err != nil {
		return repositoryLinks{}
	}
	switch parsed.Scheme {
	case "https", "http", "ssh", "git":
	default:
		return repositoryLinks{}
	}
	hostname := strings.ToLower(parsed.Hostname())
	gitlab := hostname == "gitlab.com" || strings.HasPrefix(hostname, "gitlab.") || strings.Contains(hostname, ".gitlab.")
	if hostname != "github.com" && !gitlab {
		return repositoryLinks{}
	}
	path := strings.TrimSuffix(strings.Trim(parsed.Path, "/"), ".git")
	segments := strings.Split(path, "/")
	if len(segments) < 2 || (!gitlab && len(segments) != 2) {
		return repositoryLinks{}
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return repositoryLinks{}
		}
	}
	scheme, host := parsed.Scheme, parsed.Host
	if scheme == "ssh" || scheme == "git" {
		scheme, host = "https", hostname
	}
	// Construct a new URL to discard userinfo, query strings, and fragments.
	base := (&url.URL{Scheme: scheme, Host: host, Path: "/" + path}).String()
	return repositoryLinks{base: base, gitlab: gitlab}
}

func (links repositoryLinks) commit(hash string) string {
	if links.base == "" {
		return ""
	}
	if links.gitlab {
		return links.base + "/-/commit/" + url.PathEscape(hash)
	}
	return links.base + "/commit/" + url.PathEscape(hash)
}

func (links repositoryLinks) comparison(from, to string) string {
	if links.base == "" {
		return ""
	}
	prefix := links.base
	if links.gitlab {
		prefix += "/-"
	}
	if from == "" {
		return prefix + "/commits/" + url.PathEscape(to)
	}
	return prefix + "/compare/" + url.PathEscape(from) + "..." + url.PathEscape(to)
}
