// Copyright 2024 Defense Unicorns
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
	github "github.com/google/go-github/v69/github"
	"github.com/zarf-dev/zarf/src/pkg/message"
)

type Platform struct{}

func (Platform) TagAndRelease(flavor types.Flavor, tokenVarName string, packageNameFlag string) error {
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

	tagName := utils.GetFormattedVersion(packageNameFlag, flavor.Version, flavor.Name)
	releaseName := fmt.Sprintf("%s %s", zarfPackageName, tagName)

	// Create the release
	release := &github.RepositoryRelease{
		TagName:              github.Ptr(tagName),
		Name:                 github.Ptr(releaseName),
		Body:                 github.Ptr(releaseName), //TODO @corang release notes
		GenerateReleaseNotes: github.Ptr(true),
	}

	message.Infof("Creating release %s-%s\n", flavor.Version, flavor.Name)

	_, response, err := githubClient.Repositories.CreateRelease(context.Background(), owner, repoName, release)

	err = platforms.ReleaseExists(422, response.StatusCode, err, `already_exists`, zarfPackageName, flavor)
	if err != nil {
		return err
	}
	return nil
}

func createGitHubTag(tagName string, releaseName string, hash string) *github.Tag {
	tag := &github.Tag{
		Tag:     github.Ptr(tagName),
		Message: github.Ptr(releaseName),
		Object: &github.GitObject{
			SHA:  github.Ptr(hash),
			Type: github.Ptr("commit"),
		},
		Tagger: &github.CommitAuthor{
			Name:  github.Ptr(os.Getenv("GITHUB_ACTOR")),
			Email: github.Ptr(os.Getenv("GITHUB_ACTOR") + "@users.noreply.github.com"),
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
