// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package gitlab

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/platforms"
	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type Platform struct{}

func (Platform) TagAndRelease(flavor types.Flavor, tokenVarName string, packageNameFlag string) error {
	remoteURL, defaultBranch, err := utils.GetRepoInfo()
	if err != nil {
		return err
	}

	// Parse the GitLab base URL from the remote URL
	gitlabBaseURL, err := getGitlabBaseUrl(remoteURL)
	if err != nil {
		return err
	}

	// Create a new GitLab client
	gitlabClient, err := gitlab.NewClient(os.Getenv(tokenVarName), gitlab.WithBaseURL(gitlabBaseURL))
	if err != nil {
		return err
	}

	zarfPackageName, err := utils.GetPackageName()
	if err != nil {
		return err
	}

	// setup the release options
	releaseOpts := createReleaseOptions(zarfPackageName, flavor, defaultBranch, packageNameFlag)

	fmt.Printf("Creating release %s-%s\n", flavor.Version, flavor.Name)

	err = platforms.VerifyEnvVar("CI_PROJECT_ID")
	if err != nil {
		return err
	}

	// Create the release
	_, response, err := gitlabClient.Releases.CreateRelease(os.Getenv("CI_PROJECT_ID"), releaseOpts)

	err = platforms.ReleaseExists(409, response.StatusCode, err, `message: Release already exists`, zarfPackageName, flavor)
	if err != nil {
		return err
	}
	return nil
}

func createReleaseOptions(zarfPackageName string, flavor types.Flavor, branchRef string, packageNameFlag string) *gitlab.CreateReleaseOptions {
	return &gitlab.CreateReleaseOptions{
		Name:        gitlab.Ptr(fmt.Sprintf("%s %s-%s", zarfPackageName, flavor.Version, flavor.Name)),
		TagName:     gitlab.Ptr(utils.GetFormattedVersion(packageNameFlag, flavor.Version, flavor.Name)),
		Description: gitlab.Ptr(fmt.Sprintf("%s %s-%s", zarfPackageName, flavor.Version, flavor.Name)),
		Ref:         gitlab.Ptr(branchRef),
	}
}

func getGitlabBaseUrl(remoteURL string) (gitlabBaseURL string, err error) {
	if strings.Contains(remoteURL, "gitlab.com") {
		return "https://gitlab.com/api/v4", nil
	}

	parsedURL, err := url.Parse(remoteURL)
	if err != nil {
		regex := regexp.MustCompile(`@([^:/]+)`)
		matches := regex.FindStringSubmatch(remoteURL)
		if len(matches) > 1 {
			return fmt.Sprintf("https://%s/api/v4", matches[1]), nil
		}
		return "", fmt.Errorf("error parsing GitLab base URL from remote URL: %s", remoteURL)
	}

	return fmt.Sprintf("%s://%s/api/v4", parsedURL.Scheme, parsedURL.Host), nil
}
