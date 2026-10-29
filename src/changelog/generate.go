// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package changelog

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
)

// GenerateOptions selects a release and optional artifact destinations. Paths
// are relative to Directory, which contains releaser.yaml.
type GenerateOptions struct {
	Directory    string
	Selection    Selection
	Revisions    RevisionRange
	IncludePaths []string
	Output       string
	Changelog    string
}

// Generation contains rendered Markdown and files ready for WriteArtifacts.
// It exposes no Git objects or intermediate release models.
type Generation struct {
	Notes     []byte
	Artifacts []Artifact
}

// Generate reads local configuration and history, selects and groups changes,
// and renders notes plus any requested changelog update. It does not write
// artifacts; errors leave existing files untouched.
func Generate(ctx context.Context, options GenerateOptions) (Generation, error) {
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return Generation{}, fmt.Errorf("resolve release directory: %w", err)
	}
	configPath := filepath.Join(directory, "releaser.yaml")
	var config types.ReleaseConfig
	if err := utils.LoadYaml(configPath, &config); err != nil {
		return Generation{}, fmt.Errorf("load release configuration %q: %w", configPath, err)
	}
	if err := config.Validate(); err != nil {
		return Generation{}, fmt.Errorf("validate release configuration %q: %w", configPath, err)
	}
	target, err := resolveTarget(config, options.Selection)
	if err != nil {
		return Generation{}, err
	}
	history, err := readHistory(ctx, directory, options.Revisions)
	if err != nil {
		return Generation{}, err
	}
	commits, err := filterCommits(ctx, history, directory, target, options.IncludePaths)
	if err != nil {
		return Generation{}, err
	}
	release := releaseData{Target: target, To: history.To.Hash.String(), RevisionDate: history.To.Committer.When, Sections: groupCommits(commits)}
	if history.From != nil {
		release.From = history.From.Hash.String()
	}
	notes := renderNotes(release, history.Origin)
	var artifacts []Artifact
	if options.Output != "" {
		artifacts = append(artifacts, Artifact{Path: artifactPath(directory, options.Output), Content: notes})
	}
	if options.Changelog != "" {
		path := artifactPath(directory, options.Changelog)
		existing, err := readArtifact(path)
		if err != nil {
			return Generation{}, fmt.Errorf("read changelog %q: %w", path, err)
		}
		updated, err := updateChangelog(existing, release, history.Origin)
		if err != nil {
			return Generation{}, fmt.Errorf("update changelog %q: %w", path, err)
		}
		artifacts = append(artifacts, Artifact{Path: path, Content: updated})
	}
	if err := ctx.Err(); err != nil {
		return Generation{}, err
	}
	return Generation{Notes: notes, Artifacts: artifacts}, nil
}

func artifactPath(directory, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(directory, path)
}
