package gitlab

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/defenseunicorns/uds-releaser/src/types"
	"github.com/defenseunicorns/uds-releaser/src/utils"
	gitlab "github.com/xanzy/go-gitlab"
)

type Platform struct{}

func (Platform) TagAndRelease(flavor types.Flavor, tokenVarName string) error {
	remoteURL, defaultBranch, err := utils.GetRepoInfo()
	if err != nil {
		return err
	}

	fmt.Println("Remote URL: ", remoteURL)

	// Parse the GitLab base URL from the remote URL
	gitlabBaseURL, err := getGitlabBaseUrl(remoteURL)
	if err != nil {
		return err
	}

	fmt.Println("Base URL: ", gitlabBaseURL)

	fmt.Printf("Default branch: %s\n", defaultBranch)

	fmt.Println("token var name: ", tokenVarName)

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
	releaseOpts := createReleaseOptions(zarfPackageName, flavor, defaultBranch)

	fmt.Printf("Creating release %s-%s\n", flavor.Version, flavor.Name)

	// Create the release
	release, _, err := gitlabClient.Releases.CreateRelease(os.Getenv("CI_PROJECT_ID"), releaseOpts)
	if err != nil {
		fmt.Println("Error creating release: ", err)
		return err
	}

	fmt.Printf("Release %s created\n", release.Name)

	return nil
}

func createReleaseOptions(zarfPackageName string, flavor types.Flavor, branchRef string) *gitlab.CreateReleaseOptions {
	return &gitlab.CreateReleaseOptions{
		Name:        gitlab.Ptr(fmt.Sprintf("%s %s-%s", zarfPackageName, flavor.Version, flavor.Name)),
		TagName:     gitlab.Ptr(fmt.Sprintf("%s-%s", flavor.Version, flavor.Name)),
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
