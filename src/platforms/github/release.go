// Copyright 2024-2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package github

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/defenseunicorns/uds-pk/src/platforms"
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	github "github.com/google/go-github/v92/github"
)

type Platform struct{}

func (Platform) TagAndRelease(flavor types.Flavor, tokenVarName string, packageNameFlag string) error {
	remoteURL, _, err := utils.GetRepoInfo()
	if err != nil {
		return err
	}

	// Create a new GitHub client
	// Set the authentication token
	githubClient, err := github.NewClient(github.WithAuthToken(os.Getenv(tokenVarName)))
	if err != nil {
		return err
	}

	owner, repoName, err := getGithubOwnerAndRepo(remoteURL)
	if err != nil {
		return err
	}

	// Create the tag
	zarfPackageName, err := utils.GetPackageName()
	if err != nil {
		return err
	}

	tagName := utils.GetFormattedVersion(packageNameFlag, flavor.Version, flavor.Name)
	releaseName := fmt.Sprintf("%s %s", zarfPackageName, tagName)
	body := releaseName
	generateReleaseNotes := true

	// Create the release
	release := github.CreateReleaseRequest{
		TagName:              tagName,
		Name:                 &releaseName,
		Body:                 &body, //TODO @corang release notes
		GenerateReleaseNotes: &generateReleaseNotes,
	}

	fmt.Printf("Creating release %s\n", releaseName)

	_, response, err := githubClient.Repositories.CreateRelease(context.Background(), owner, repoName, release)

	err = platforms.ReleaseExists(422, response.StatusCode, err, `already_exists`, zarfPackageName, flavor)
	if err != nil {
		return err
	}
	return nil
}

func (Platform) BundleTagAndRelease(bundle types.Bundle, tokenVarName string) error {
	remoteURL, _, err := utils.GetRepoInfo()
	if err != nil {
		return err
	}

	// Create a new GitHub client
	// Set the authentication token
	githubClient, err := github.NewClient(github.WithAuthToken(os.Getenv(tokenVarName)))
	if err != nil {
		return err
	}

	owner, repoName, err := getGithubOwnerAndRepo(remoteURL)
	if err != nil {
		return err
	}

	// Create the tag
	tagName := utils.GetFormattedVersion(bundle.Name, bundle.Version, "")
	releaseName := fmt.Sprintf("%s %s", bundle.Name, tagName)
	body := releaseName
	generateReleaseNotes := true

	// Create the release
	release := github.CreateReleaseRequest{
		TagName:              tagName,
		Name:                 &releaseName,
		Body:                 &body, //TODO @corang release notes
		GenerateReleaseNotes: &generateReleaseNotes,
	}

	fmt.Printf("Creating release %s\n", releaseName)

	_, response, err := githubClient.Repositories.CreateRelease(context.Background(), owner, repoName, release)

	err = platforms.ReleaseExists(422, response.StatusCode, err, `already_exists`, bundle.Name, types.Flavor{Version: bundle.Version})
	if err != nil {
		return err
	}
	return nil
}

func createGitHubTag(tagName string, releaseName string, hash string) *github.Tag {
	objectType := "commit"
	actorName := os.Getenv("GITHUB_ACTOR")
	actorEmail := os.Getenv("GITHUB_ACTOR") + "@users.noreply.github.com"

	tag := &github.Tag{
		Tag:     &tagName,
		Message: &releaseName,
		Object: &github.GitObject{
			SHA:  &hash,
			Type: &objectType,
		},
		Tagger: &github.CommitAuthor{
			Name:  &actorName,
			Email: &actorEmail,
			Date:  &github.Timestamp{Time: time.Now()},
		},
	}
	return tag
}

func getGithubOwnerAndRepo(remoteURL string) (string, string, error) {
	// Parse the GitHub owner and repository name from the remote URL
	// https://regex101.com/r/zdpJ9Q/1 Extract the owner and repository name from the remote URL using capture groups
	//   only match remoteURLs that contain github.com
	ownerRepoRegex := regexp.MustCompile(`github\.com[:\/](.*)\/(.*?)(?:\.git|$)`)
	matches := ownerRepoRegex.FindStringSubmatch(remoteURL)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("could not parse GitHub owner and repository name from remote URL: %s", remoteURL)
	}

	owner := matches[1]
	repo := matches[2]

	return owner, repo, nil
}
