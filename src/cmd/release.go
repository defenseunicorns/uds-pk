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
var packageName string
var checkBoolOutput bool
var showVersionOnly bool
var gitlabTokenVarName string
var githubTokenVarName string
var bundleName string
var packageOnly bool

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check [flavor]",
	Short: "Check if a release is necessary",
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

		formattedVersion := utils.GetFormattedVersion(packageName, currentFlavor.Version, currentFlavor.Name)

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
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if packageOnly && bundleName != "" {
			return errors.New("cannot specify both --package-only and --bundle")
		}
		if packageName != "" && bundleName != "" {
			return errors.New("cannot specify both --package and --bundle")
		}
		if len(args) > 0 && bundleName != "" {
			return errors.New("cannot specify both a flavor argument and --bundle")
		}
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

		if bundleName != "" {
			bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
			if err != nil {
				return err
			}

			return version.UpdateBundleYamlOnly(bundle)
		} else {

			path, currentFlavor, err := utils.GetFlavorConfig(flavor, releaseConfig, packageName)
			if err != nil {
				return err
			}
			return version.UpdateYamls(currentFlavor, path, packageOnly)
		}
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
	releaseCmd.PersistentFlags().StringVarP(&packageName, "package", "p", "", "Name of package to run uds-pk against. Must match an entry under packages in the releaser.yaml file. If not provided, the top level flavors will be used.")

	checkCmd.Flags().BoolVarP(&checkBoolOutput, "boolean", "b", false, "Switch the output string to a true/false based on if a release is necessary. True if a release is necessary, false if not.")

	showCmd.Flags().BoolVarP(&showVersionOnly, "version-only", "v", false, "Show only the version without flavor appended")

	gitlabCmd.Flags().StringVarP(&gitlabTokenVarName, "token-var-name", "t", "GITLAB_RELEASE_TOKEN", "Environment variable name for GitLab token")
	githubCmd.Flags().StringVarP(&githubTokenVarName, "token-var-name", "t", "GITHUB_TOKEN", "Environment variable name for GitHub token")

	updateYamlCmd.Flags().StringVarP(&bundleName, "bundle", "b", "", "Name of the bundle to update, mutually exclusive with any package flags or providing a flavor")
	updateYamlCmd.Flags().BoolVarP(&packageOnly, "package-only", "P", false, "Only update the package version, ignore the bundle")
}
