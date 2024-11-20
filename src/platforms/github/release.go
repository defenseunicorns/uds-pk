// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package github

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/defenseunicorns/uds-releaser/src/types"
	"github.com/defenseunicorns/uds-releaser/src/utils"
	github "github.com/google/go-github/v66/github"
)

type Platform struct{}

func (Platform) TagAndRelease(flavor types.Flavor, tokenVarName string) error {
	remoteURL, _, err := utils.GetRepoInfo()
	if err != nil {
		return err
	}

	// Create a new GitHub client
	githubClient := github.NewClient(nil)

	// Set the authentication token
	githubClient = githubClient.WithAuthToken(os.Getenv(tokenVarName))

	owner, repoName, err := getGithubOwnerAndRepo(remoteURL)
	if err != nil {
		return err
	}

	// Create the tag
	zarfPackageName, err := utils.GetPackageName()
	if err != nil {
		return err
	}

	tagName := fmt.Sprintf("%s-%s", flavor.Version, flavor.Name)
	releaseName := fmt.Sprintf("%s %s", zarfPackageName, tagName)

	// Create the release
	release := &github.RepositoryRelease{
		TagName:              github.String(tagName),
		Name:                 github.String(releaseName),
		Body:                 github.String(releaseName), //TODO @corang release notes
		GenerateReleaseNotes: github.Bool(true),
	}

	_, _, err = githubClient.Repositories.CreateRelease(context.Background(), owner, repoName, release)
	if err != nil {
		return err
	}
	return nil
}

func createGitHubTag(tagName string, releaseName string, hash string) *github.Tag {
	tag := &github.Tag{
		Tag:     github.String(tagName),
		Message: github.String(releaseName),
		Object: &github.GitObject{
			SHA:  github.String(hash),
			Type: github.String("commit"),
		},
		Tagger: &github.CommitAuthor{
			Name:  github.String(os.Getenv("GITHUB_ACTOR")),
			Email: github.String(os.Getenv("GITHUB_ACTOR") + "@users.noreply.github.com"),
			Date:  &github.Timestamp{Time: time.Now()},
		},
	}
	return tag
}

func getGithubOwnerAndRepo(remoteURL string) (string, string, error) {
	// Parse the GitHub owner and repository name from the remote URL
	ownerRepoRegex := regexp.MustCompile(`github\.com[:/](.*)\/(.*?)(?:\.git|$)`)
	matches := ownerRepoRegex.FindStringSubmatch(remoteURL)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("could not parse GitHub owner and repository name from remote URL: %s", remoteURL)
	}

	owner := matches[1]
	repo := matches[2]

	return owner, repo, nil
}
