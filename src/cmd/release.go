// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/platforms"
	"github.com/defenseunicorns/uds-pk/src/platforms/github"
	"github.com/defenseunicorns/uds-pk/src/platforms/gitlab"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/defenseunicorns/uds-pk/src/version"
	"github.com/spf13/cobra"
)

var releaseDir string
var packageName string
var checkBoolOutput bool
var usePlainHTTP bool
var baseRepo string
var arch string
var showVersionOnly bool
var gitlabTokenVarName string
var githubTokenVarName string
var showTag bool

var schemeWithSlashes = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

func checkPackageExists(repositoryURL, tag, arch string, logger *slog.Logger) (bool, error) {
	httpScheme := "https"
	if usePlainHTTP {
		httpScheme = "http"
	}
	logger.Debug("Checking if package exists", slog.String("repository", repositoryURL), slog.String("tag", tag), slog.String("arch", arch))
	if !schemeWithSlashes.MatchString(repositoryURL) {
		repositoryURL = fmt.Sprintf("%s://%s", httpScheme, repositoryURL)
	}

	// repositoryURL is something like https://ghcr.io/defenseunicorns/packages/uds
	// we need to transform it to v2 api for checking metadata, something like
	// https://ghcr.io/v2/defenseunicorns/packages/uds/gitlab-runner/manifests/$TAG
	parsedUrl, err := url.Parse(repositoryURL)
	if err != nil {
		logger.Warn("Failed to parse repository URL. Assuming the release is not published", slog.Any("err", err))
		return false, err
	}
	metadataUrl := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", httpScheme, parsedUrl.Host, parsedUrl.Path[1:], tag)
	logger.Debug("Checking if package exists", slog.String("metadataUrl", metadataUrl))
	index, err := utils.FetchImageIndex(metadataUrl, logger)
	if err != nil {
		return false, err
	}
	for _, manifest := range index.Manifests {
		if manifest.Platform.Architecture == arch {
			return true, nil
		}
	}
	return false, nil
}

var checkCmd = &cobra.Command{
	Use:   "check [flavor]",
	Short: "Check if a release is necessary",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		logger := Logger(&ctx)

		if strings.HasSuffix(baseRepo, "/") {
			baseRepo = baseRepo[:len(baseRepo)-1]
		}
		logger.Debug("Checking if package exists", slog.String("baseRepo", baseRepo), slog.String("arch", arch))

		var err error
		zarfPackageName, err := utils.GetPackageName()
		if err != nil {
			return err
		}
		logger.Debug("Package name", slog.String("zarfPackageName", zarfPackageName))

		rootCmd.SilenceUsage = true
		var flavor string

		if len(args) == 0 {
			flavor = ""
		} else {
			flavor = args[0]
		}
		logger.Debug("flavor", slog.String("flavor", flavor))

		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}
		logger.Debug("read release config")

		_, currentFlavor, err := utils.GetFlavorConfig(flavor, releaseConfig, packageName)
		if err != nil {
			return err
		}
		logger.Debug("read current flavor", slog.String("version", currentFlavor.Version), slog.String("name", currentFlavor.Name))

		formattedVersion := utils.GetFormattedVersion(packageName, currentFlavor.Version, currentFlavor.Name)

		tagExists, err := utils.DoesTagExist(formattedVersion)
		if err != nil {
			return err
		}
		effectiveResult := false
		// if the tag doesn't exist, we're sure we have to re-publish:
		if tagExists {
			repoTag := currentFlavor.Version
			if currentFlavor.Name != "" {
				repoTag = fmt.Sprintf("%s-%s", repoTag, currentFlavor.Name)
			}

			var repositoryUrl string
			if flavor == "unicorn" {
				repositoryUrl = baseRepo + "/private/" + zarfPackageName
			} else {
				repositoryUrl = baseRepo + "/" + zarfPackageName
			}

			logger.Debug("Determined target repository", slog.String("repository", repositoryUrl))

			// otherwise let's see if publishing was successful:
			result, err := checkPackageExists(repositoryUrl, repoTag, arch, logger)
			if err != nil {
				logger.Warn("Failed to check if package exists, assuming it doesn't", slog.Any("err", err))
				effectiveResult = true
			} else {
				effectiveResult = !result
			}

		} else {
			effectiveResult = true
		}

		if effectiveResult {
			if checkBoolOutput {
				fmt.Println("true")
			} else {
				logger.Info("Version is not published", slog.String("version", formattedVersion))
			}
		} else {
			if checkBoolOutput {
				fmt.Println("false")
			} else {
				logger.Info("Version is already tagged", slog.String("version", formattedVersion))
				return errors.New("no release necessary")
			}
		}
		return nil
	},
}

// showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show [flavor]",
	Short: "Show the current version",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCmd.SilenceUsage = true

		var flavor string
		if len(args) == 0 {
			flavor = ""
		} else {
			flavor = args[0]
		}

		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		_, currentFlavor, err := utils.GetFlavorConfig(flavor, releaseConfig, packageName)
		if err != nil {
			return err
		}

		if showVersionOnly {
			fmt.Println(currentFlavor.Version)
		} else {
			fmt.Println(utils.GetFormattedVersion("", currentFlavor.Version, currentFlavor.Name))
		}

		return nil
	},
}

// gitlabCmd represents the gitlab command
var gitlabCmd = &cobra.Command{
	Use:   "gitlab [flavor]",
	Short: "Create a tag and release on GitLab",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var flavor string
		if len(args) == 0 {
			flavor = ""
		} else {
			flavor = args[0]
		}

		return platforms.LoadAndTag(releaseDir, flavor, gitlabTokenVarName, gitlab.Platform{}, packageName)
	},
}

// githubCmd represents the github command
var githubCmd = &cobra.Command{
	Use:   "github [flavor]",
	Short: "Create a tag and release on GitHub",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var flavor string
		if len(args) == 0 {
			flavor = ""
		} else {
			flavor = args[0]
		}

		return platforms.LoadAndTag(releaseDir, flavor, githubTokenVarName, github.Platform{}, packageName)
	},
}

// updateYamlCmd represents the updateyaml command
var updateYamlCmd = &cobra.Command{
	Use:     "update-yaml [flavor]",
	Aliases: []string{"u"},
	Short:   "Update the version fields in the zarf.yaml and uds-bundle.yaml",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCmd.SilenceUsage = true

		var flavor string
		if len(args) == 0 {
			flavor = ""
		} else {
			flavor = args[0]
		}

		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		path, currentFlavor, err := utils.GetFlavorConfig(flavor, releaseConfig, packageName)
		if err != nil {
			return err
		}

		return version.UpdateYamls(currentFlavor, path)
	},
}

// releaseCmd represents the release command
var releaseCmd = &cobra.Command{
	Use:   "release platform",
	Short: "Collection of commands for releasing on different platforms",
}

var bundleCmd = &cobra.Command{
	Use:   "bundle cmd",
	Short: "Collection of commands for releasing bundles",
}

var updateBundleYaml = &cobra.Command{
	Use:     "update-yaml BUNDLE_NAME",
	Aliases: []string{"ub"},
	Short:   "Update the version field in the specified uds-bundle.yaml",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCmd.SilenceUsage = true

		bundleName := args[0]

		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
		if err != nil {
			return err
		}

		return version.UpdateBundleYamlOnly(bundle)
	},
}

var checkBundleCommand = &cobra.Command{
	Use:   "check BUNDLE_NAME",
	Short: "Check if a release is necessary for the specified bundle",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCmd.SilenceUsage = true

		bundleName := args[0]

		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
		if err != nil {
			return err
		}

		formattedVersion := utils.GetFormattedVersion(bundle.Name, bundle.Version, "")

		tagExists, err := utils.DoesTagExist(formattedVersion)
		if err != nil {
			return err
		}
		if tagExists {
			if checkBoolOutput {
				fmt.Println("false")
			} else {
				fmt.Printf("Version %s is already tagged\n", formattedVersion)
				return errors.New("no release necessary")
			}
		} else {
			if checkBoolOutput {
				fmt.Println("true")
			} else {
				fmt.Printf("Version %s is not tagged\n", formattedVersion)
			}
		}
		return nil
	},
}

var showBundleCommand = &cobra.Command{
	Use:   "show BUNDLE_NAME",
	Short: "Show the current version for the specified bundle",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCmd.SilenceUsage = true

		bundleName := args[0]

		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
		if err != nil {
			return err
		}

		if showTag {
			fmt.Println(utils.GetFormattedVersion(bundle.Name, bundle.Version, ""))
		} else {
			fmt.Println(bundle.Version)
		}
		return nil
	},
}

var bundleGitlabCmd = &cobra.Command{
	Use:   "gitlab BUNDLE_NAME",
	Short: "Create a tag and release for the specified bundle on GitLab",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bundleName := args[0]

		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
		if err != nil {
			return err
		}

		gitlab := gitlab.Platform{}
		return gitlab.BundleTagAndRelease(bundle, gitlabTokenVarName)
	},
}

var bundleGithubCmd = &cobra.Command{
	Use:   "github BUNDLE_NAME",
	Short: "Create a tag and release for the specified bundle on GitHub",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bundleName := args[0]

		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
		if err != nil {
			return err
		}

		github := github.Platform{}
		return github.BundleTagAndRelease(bundle, githubTokenVarName)
	},
}

func init() {
	rootCmd.AddCommand(releaseCmd)

	releaseCmd.AddCommand(checkCmd)
	releaseCmd.AddCommand(showCmd)
	releaseCmd.AddCommand(gitlabCmd)
	releaseCmd.AddCommand(githubCmd)
	releaseCmd.AddCommand(updateYamlCmd)

	releaseCmd.PersistentFlags().StringVarP(&releaseDir, "dir", "d", ".", "Path to the directory containing the releaser.yaml file")

	checkCmd.Flags().BoolVarP(&checkBoolOutput, "boolean", "b", false, "Switch the output string to a true/false based on if a release is necessary. True if a release is necessary, false if not.")
	checkCmd.Flags().StringVarP(&baseRepo, "base-repo", "r", "ghcr.io/uds-packages", "Repository URL.")
	checkCmd.Flags().StringVarP(&arch, "arch", "a", "amd64", "Architecture to check (e.g. amd64, arm64). amd64 by default.")
	checkCmd.Flags().BoolVar(&usePlainHTTP, "plain-http", false, "TEST ONLY Use plain HTTP instead of HTTPS for repository URL")

	showCmd.Flags().BoolVarP(&showVersionOnly, "version-only", "v", false, "Show only the version without flavor appended")

	gitlabCmd.Flags().StringVarP(&gitlabTokenVarName, "token-var-name", "t", "GITLAB_RELEASE_TOKEN", "Environment variable name for GitLab token")
	githubCmd.Flags().StringVarP(&githubTokenVarName, "token-var-name", "t", "GITHUB_TOKEN", "Environment variable name for GitHub token")

	// Can't mark as persistent flag because it's not applicable to bundle commands
	for _, cmd := range []*cobra.Command{releaseCmd, checkCmd, showCmd, gitlabCmd, githubCmd, updateYamlCmd} {
		cmd.Flags().StringVarP(&packageName, "package", "p", "", "Name of package to run uds-pk against. Must match an entry under packages in the releaser.yaml file. If not provided, the top level flavors will be used.")
	}

	releaseCmd.AddCommand(bundleCmd)

	bundleCmd.AddCommand(checkBundleCommand)
	bundleCmd.AddCommand(showBundleCommand)
	bundleCmd.AddCommand(bundleGitlabCmd)
	bundleCmd.AddCommand(bundleGithubCmd)
	bundleCmd.AddCommand(updateBundleYaml)

	bundleGitlabCmd.Flags().StringVarP(&gitlabTokenVarName, "token-var-name", "t", "GITLAB_RELEASE_TOKEN", "Environment variable name for GitLab token")
	bundleGithubCmd.Flags().StringVarP(&githubTokenVarName, "token-var-name", "t", "GITHUB_TOKEN", "Environment variable name for GitHub token")

	checkBundleCommand.Flags().BoolVarP(&checkBoolOutput, "boolean", "b", false, "Switch the output string to a true/false based on if a release is necessary. True if a release is necessary, false if not.")

	showBundleCommand.Flags().BoolVarP(&showTag, "tag", "t", false, "Show the full tag including bundle name instead of just the version")
}
