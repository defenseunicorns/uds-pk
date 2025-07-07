// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"errors"
	"fmt"

	"github.com/defenseunicorns/uds-pk/src/platforms"
	"github.com/defenseunicorns/uds-pk/src/platforms/github"
	"github.com/defenseunicorns/uds-pk/src/platforms/gitlab"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/defenseunicorns/uds-pk/src/version"
	"github.com/spf13/cobra"
)

var releaseDir string
var checkBoolOutput bool
var showVersionOnly bool
var gitlabTokenVarName string
var githubTokenVarName string

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check flavor",
	Short: "Check if release is necessary for given flavor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		currentFlavor, err := utils.GetFlavorConfig(args[0], releaseConfig)
		if err != nil {
			return err
		}

		rootCmd.SilenceUsage = true

		versionAndFlavor := fmt.Sprintf("%s-%s", currentFlavor.Version, currentFlavor.Name)

		tagExists, err := utils.DoesTagExist(versionAndFlavor)
		if err != nil {
			return err
		}
		if tagExists {
			if checkBoolOutput {
				fmt.Println("false")
			} else {
				fmt.Printf("Version %s is already tagged\n", versionAndFlavor)
				return errors.New("no release necessary")
			}
		} else {
			if checkBoolOutput {
				fmt.Println("true")
			} else {
				fmt.Printf("Version %s is not tagged\n", versionAndFlavor)
			}
		}
		return nil
	},
}

// showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show flavor",
	Short: "Show the current version for a given flavor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		currentFlavor, err := utils.GetFlavorConfig(args[0], releaseConfig)
		if err != nil {
			return err
		}

		rootCmd.SilenceUsage = true

		if showVersionOnly {
			fmt.Printf("%s\n", currentFlavor.Version)
		} else {
			fmt.Printf("%s-%s\n", currentFlavor.Version, currentFlavor.Name)
		}

		return nil
	},
}

// gitlabCmd represents the gitlab command
var gitlabCmd = &cobra.Command{
	Use:   "gitlab flavor",
	Short: "Create a tag and release on GitLab based on flavor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return platforms.LoadAndTag(releaseDir, args[0], gitlabTokenVarName, gitlab.Platform{})
	},
}

// githubCmd represents the github command
var githubCmd = &cobra.Command{
	Use:   "github flavor",
	Short: "Create a tag and release on GitHub based on flavor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return platforms.LoadAndTag(releaseDir, args[0], githubTokenVarName, github.Platform{})
	},
}

// updateYamlCmd represents the updateyaml command
var updateYamlCmd = &cobra.Command{
	Use:     "update-yaml flavor",
	Aliases: []string{"u"},
	Short:   "Update the version fields in the zarf.yaml and uds-bundle.yaml based on flavor",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		releaseConfig, err := utils.LoadReleaseConfig(releaseDir)
		if err != nil {
			return err
		}

		currentFlavor, err := utils.GetFlavorConfig(args[0], releaseConfig)
		if err != nil {
			return err
		}

		rootCmd.SilenceUsage = true

		return version.UpdateYamls(currentFlavor)
	},
}

// releaseCmd represents the release command
var releaseCmd = &cobra.Command{
	Use:   "release platform",
	Short: "Collection of commands for releasing on different platforms",
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

	showCmd.Flags().BoolVarP(&showVersionOnly, "version-only", "v", false, "Show only the version without flavor appended")

	gitlabCmd.Flags().StringVarP(&gitlabTokenVarName, "token-var-name", "t", "GITLAB_RELEASE_TOKEN", "Environment variable name for GitLab token")
	githubCmd.Flags().StringVarP(&githubTokenVarName, "token-var-name", "t", "GITHUB_TOKEN", "Environment variable name for GitHub token")
}
