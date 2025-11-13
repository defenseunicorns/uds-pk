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

var schemeWithSlashes = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

func checkPackageExists(repositoryURL, tag, arch string, usePlainHTTP bool, logger *slog.Logger) (bool, error) {
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

type CheckOptions struct {
	usePlainHTTP     bool
	baseRepo         string
	arch             string
	releaseDir       string
	packageName      string
	skipPublishCheck bool
	checkBoolOutput  bool
}

func checkCmd() *cobra.Command {
	options := &CheckOptions{}
	cmd := &cobra.Command{
		Use:   "check [flavor]",
		Short: "Check if a release is necessary",
		Args:  cobra.MaximumNArgs(1),
		RunE:  options.run,
	}
	cmd.Flags().BoolVarP(&options.checkBoolOutput, "boolean", "b", false, "Switch the output string to a true/false based on if a release is necessary. True if a release is necessary, false if not.")
	cmd.Flags().StringVarP(&options.baseRepo, "base-repo", "r", "ghcr.io/uds-packages", "Repository URL.")
	cmd.Flags().StringVarP(&options.arch, "arch", "a", "amd64", "Architecture to check (e.g. amd64, arm64). amd64 by default.")
	cmd.Flags().BoolVar(&options.skipPublishCheck, "skip-publish-check", false, "If enabled, the release check will be based solely on the tag existence.")
	cmd.Flags().BoolVar(&options.usePlainHTTP, "plain-http", false, "TEST ONLY Use plain HTTP instead of HTTPS for repository URL")
	addPackageFlag(&options.packageName, cmd)
	addReleaseDirFlag(&options.releaseDir, cmd)
	return cmd
}

func (options *CheckOptions) run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	log := Logger(&ctx)

	baseRepo := strings.TrimSuffix(options.baseRepo, "/")

	log.Debug("Checking if package exists", slog.String("baseRepo", baseRepo), slog.String("arch", options.arch))

	var err error
	zarfPackageName, err := utils.GetPackageName()
	if err != nil {
		return err
	}
	log.Debug("Package name", slog.String("zarfPackageName", zarfPackageName))

	rootCmd.SilenceUsage = true
	var flavor string

	if len(args) == 0 {
		flavor = ""
	} else {
		flavor = args[0]
	}
	log.Debug("flavor", slog.String("flavor", flavor))

	releaseConfig, err := utils.LoadReleaseConfig(options.releaseDir)
	if err != nil {
		return err
	}
	log.Debug("read release config")

	_, currentFlavor, err := utils.GetFlavorConfig(flavor, releaseConfig, options.packageName)
	if err != nil {
		return err
	}
	log.Debug("read current flavor", slog.String("version", currentFlavor.Version), slog.String("name", currentFlavor.Name))

	formattedVersion := utils.GetFormattedVersion(options.packageName, currentFlavor.Version, currentFlavor.Name)

	tagExists, err := utils.DoesTagExist(formattedVersion)
	if err != nil {
		return err
	}
	effectiveResult := false
	// if the tag doesn't exist, we're sure we have to re-publish:
	if tagExists {
		if options.skipPublishCheck {
			effectiveResult = false
		} else {
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

			log.Debug("Determined target repository", slog.String("repository", repositoryUrl))

			// otherwise let's see if publishing was successful:
			result, err := checkPackageExists(repositoryUrl, repoTag, options.arch, options.usePlainHTTP, log)
			if err != nil {
				log.Warn("Failed to check if package exists, assuming it doesn't", slog.Any("err", err))
				effectiveResult = true
			} else {
				effectiveResult = !result
			}
		}
	} else {
		effectiveResult = true
	}

	if effectiveResult {
		if options.checkBoolOutput {
			fmt.Println("true")
		} else {
			log.Info("Version is not published", slog.String("version", formattedVersion))
		}
	} else {
		if options.checkBoolOutput {
			fmt.Println("false")
		} else {
			log.Info("Version is already tagged", slog.String("version", formattedVersion))
			return errors.New("no release necessary")
		}
	}
	return nil
}

type ShowOptions struct {
	packageName     string
	releaseDir      string
	showVersionOnly bool
}

// showCmd represents the show command
func showCmd() *cobra.Command {
	options := &ShowOptions{}
	cmd := &cobra.Command{
		Use:   "show [flavor]",
		Short: "Show the current version",
		Args:  cobra.MaximumNArgs(1),
		RunE:  options.run,
	}
	cmd.Flags().BoolVarP(&options.showVersionOnly, "version-only", "v", false, "Show only the version without flavor appended")
	addPackageFlag(&options.packageName, cmd)
	addReleaseDirFlag(&options.releaseDir, cmd)
	return cmd
}
func (options *ShowOptions) run(_ *cobra.Command, args []string) error {
	rootCmd.SilenceUsage = true

	var flavor string
	if len(args) == 0 {
		flavor = ""
	} else {
		flavor = args[0]
	}
	releaseConfig, err := utils.LoadReleaseConfig(options.releaseDir)
	if err != nil {
		return err
	}

	_, currentFlavor, err := utils.GetFlavorConfig(flavor, releaseConfig, options.packageName)
	if err != nil {
		return err
	}

	if options.showVersionOnly {
		fmt.Println(currentFlavor.Version)
	} else {
		fmt.Println(utils.GetFormattedVersion("", currentFlavor.Version, currentFlavor.Name))
	}

	return nil
}

type ReleaseOptions struct {
	releaseDir   string
	packageName  string
	tokenVarName string
}

type GithubReleaseOptions ReleaseOptions
type GitlabReleaseOptions ReleaseOptions

// gitlabCmd represents the gitlab command
func gitlabCmd() *cobra.Command {
	options := &GithubReleaseOptions{}
	cmd := &cobra.Command{
		Use:   "gitlab [flavor]",
		Short: "Create a tag and release on GitLab",
		Args:  cobra.MaximumNArgs(1),
		RunE:  options.run,
	}
	addReleaseOptions(cmd, (*ReleaseOptions)(options))
	cmd.Flags().StringVarP(&options.tokenVarName, "token-var-name", "t", "GITLAB_RELEASE_TOKEN", "Environment variable name for GitLab token")
	return cmd
}

func addReleaseOptions(cmd *cobra.Command, options *ReleaseOptions) {
	addPackageFlag(&options.packageName, cmd)
	addReleaseDirFlag(&options.releaseDir, cmd)
}

func (options *GithubReleaseOptions) run(_ *cobra.Command, args []string) error {
	var flavor string
	if len(args) == 0 {
		flavor = ""
	} else {
		flavor = args[0]
	}

	return platforms.LoadAndTag(options.releaseDir, flavor, options.tokenVarName, gitlab.Platform{}, options.packageName)
}

// githubCmd represents the github command
func githubCmd() *cobra.Command {
	options := &GitlabReleaseOptions{}
	cmd := &cobra.Command{
		Use:   "github [flavor]",
		Short: "Create a tag and release on GitHub",
		Args:  cobra.MaximumNArgs(1),
		RunE:  options.run,
	}
	addReleaseOptions(cmd, (*ReleaseOptions)(options))
	cmd.Flags().StringVarP(&options.tokenVarName, "token-var-name", "t", "GITHUB_TOKEN", "Environment variable name for GitHub token")
	return cmd
}

func (options *GitlabReleaseOptions) run(_ *cobra.Command, args []string) error {
	var flavor string
	if len(args) == 0 {
		flavor = ""
	} else {
		flavor = args[0]
	}

	return platforms.LoadAndTag(options.releaseDir, flavor, options.tokenVarName, github.Platform{}, options.packageName)
}

type UpdateYamlOptions struct {
	packageName string
	releaseDir  string
}

// updateYamlCmd represents the updateyaml command
func updateYamlCmd() *cobra.Command {
	options := &UpdateYamlOptions{}
	cmd := &cobra.Command{
		Use:     "update-yaml [flavor]",
		Aliases: []string{"u"},
		Short:   "Update the version fields in the zarf.yaml and uds-bundle.yaml",
		Args:    cobra.MaximumNArgs(1),
		RunE:    options.run,
	}
	addPackageFlag(&options.packageName, cmd)
	addReleaseDirFlag(&options.releaseDir, cmd)
	return cmd
}

func (options *UpdateYamlOptions) run(_ *cobra.Command, args []string) error {
	rootCmd.SilenceUsage = true
	var flavor string
	if len(args) == 0 {
		flavor = ""
	} else {
		flavor = args[0]
	}
	releaseConfig, err := utils.LoadReleaseConfig(options.releaseDir)
	if err != nil {
		return err
	}
	path, currentFlavor, err := utils.GetFlavorConfig(flavor, releaseConfig, options.packageName)
	if err != nil {
		return err
	}
	return version.UpdateYamls(currentFlavor, path)
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

type UpdateBundleYamlOptions struct {
	releaseDir string
}

// bundle subcommand factories
func updateBundleYamlCmd() *cobra.Command {
	options := &UpdateBundleYamlOptions{}
	cmd := &cobra.Command{
		Use:     "update-yaml BUNDLE_NAME",
		Aliases: []string{"ub"},
		Short:   "Update the version field in the specified uds-bundle.yaml",
		Args:    cobra.ExactArgs(1),
		RunE:    options.run,
	}
	addReleaseDirFlag(&options.releaseDir, cmd)
	return cmd
}

func (options *UpdateBundleYamlOptions) run(_ *cobra.Command, args []string) error {
	rootCmd.SilenceUsage = true
	bundleName := args[0]
	releaseConfig, err := utils.LoadReleaseConfig(options.releaseDir)
	if err != nil {
		return err
	}
	bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
	if err != nil {
		return err
	}
	return version.UpdateBundleYamlOnly(bundle)
}

type CheckBundleOptions struct {
	releaseDir      string
	checkBoolOutput bool
}

func checkBundleCmd() *cobra.Command {
	options := &CheckBundleOptions{}
	cmd := &cobra.Command{
		Use:   "check BUNDLE_NAME",
		Short: "Check if a release is necessary for the specified bundle",
		Args:  cobra.ExactArgs(1),
		RunE:  options.run,
	}
	addReleaseDirFlag(&options.releaseDir, cmd)
	cmd.Flags().BoolVarP(&options.checkBoolOutput, "bool-output", "b", false, "If enabled, the command will output a boolean value instead of printing to stdout")
	return cmd
}

func (options *CheckBundleOptions) run(_ *cobra.Command, args []string) error {
	rootCmd.SilenceUsage = true

	bundleName := args[0]

	releaseConfig, err := utils.LoadReleaseConfig(options.releaseDir)
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
		if options.checkBoolOutput {
			fmt.Println("false")
		} else {
			fmt.Printf("Version %s is already tagged\n", formattedVersion)
			return errors.New("no release necessary")
		}
	} else {
		if options.checkBoolOutput {
			fmt.Println("true")
		} else {
			fmt.Printf("Version %s is not tagged\n", formattedVersion)
		}
	}
	return nil
}

type ShowBundleOptions struct {
	releaseDir string
	showTag    bool
}

func showBundleCommand() *cobra.Command {
	options := ShowBundleOptions{}
	cmd := &cobra.Command{
		Use:   "show BUNDLE_NAME",
		Short: "Show the current version for the specified bundle",
		Args:  cobra.ExactArgs(1),
		RunE:  options.run,
	}
	addReleaseDirFlag(&options.releaseDir, cmd)
	cmd.Flags().BoolVarP(&options.showTag, "tag", "t", false, "Show the full tag including bundle name instead of just the version")
	return cmd
}

func (options *ShowBundleOptions) run(cmd *cobra.Command, args []string) error {
	rootCmd.SilenceUsage = true

	bundleName := args[0]

	// mstodo: drop this
	ctx := cmd.Context()
	log := Logger(&ctx)
	// mstodo lower this log to Debug
	log.Info("Loading bundle config", slog.String("bundleName", bundleName), slog.String("releaseDir", options.releaseDir))
	releaseConfig, err := utils.LoadReleaseConfig(options.releaseDir)
	if err != nil {
		return err
	}

	bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
	if err != nil {
		return err
	}

	if options.showTag {
		fmt.Println(utils.GetFormattedVersion(bundle.Name, bundle.Version, ""))
	} else {
		fmt.Println(bundle.Version)
	}
	return nil
}

type BundleOptions struct {
	releaseDir   string
	tokenVarName string
}
type BundleGitlabOptions BundleOptions

func bundleGitlabCmd() *cobra.Command {
	options := BundleGitlabOptions{}
	cmd := &cobra.Command{
		Use:   "gitlab BUNDLE_NAME",
		Short: "Create a tag and release for the specified bundle on GitLab",
		Args:  cobra.ExactArgs(1),
		RunE:  options.run,
	}
	addReleaseDirFlag(&options.releaseDir, cmd)
	cmd.Flags().StringVarP(&options.tokenVarName, "token-var-name", "t", "GITLAB_RELEASE_TOKEN", "Environment variable name for GitLab token")
	return cmd
}

func (options *BundleGitlabOptions) run(_ *cobra.Command, args []string) error {
	bundleName := args[0]

	releaseConfig, err := utils.LoadReleaseConfig(options.releaseDir)
	if err != nil {
		return err
	}

	bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
	if err != nil {
		return err
	}

	gl := gitlab.Platform{}
	return gl.BundleTagAndRelease(bundle, options.tokenVarName)
}

type BundleGithubOptions BundleOptions

func bundleGithubCmd() *cobra.Command {
	options := BundleGithubOptions{}

	cmd := &cobra.Command{
		Use:   "github BUNDLE_NAME",
		Short: "Create a tag and release for the specified bundle on GitHub",
		Args:  cobra.ExactArgs(1),
		RunE:  options.run,
	}
	cmd.Flags().StringVarP(&options.tokenVarName, "token-var-name", "t", "GITLAB_RELEASE_TOKEN", "Environment variable name for GitLab token")

	return cmd
}
func (options *BundleGithubOptions) run(_ *cobra.Command, args []string) error {
	bundleName := args[0]

	releaseConfig, err := utils.LoadReleaseConfig(options.releaseDir)
	if err != nil {
		return err
	}

	bundle, err := utils.GetBundleConfig(releaseConfig, bundleName)
	if err != nil {
		return err
	}

	gh := github.Platform{}
	return gh.BundleTagAndRelease(bundle, options.tokenVarName)
}

func addPackageFlag(packageName *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(packageName, "package", "p", "", "Name of package to run uds-pk against. Must match an entry under packages in the releaser.yaml file. If not provided, the top level flavors will be used.")
}

func addReleaseDirFlag(releaseDir *string, cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(releaseDir, "dir", "d", ".", "Path to the directory containing the releaser.yaml file")
}

func init() {
	rootCmd.AddCommand(releaseCmd)

	releaseCmd.AddCommand(checkCmd())
	releaseCmd.AddCommand(showCmd())
	releaseCmd.AddCommand(gitlabCmd())
	releaseCmd.AddCommand(githubCmd())
	releaseCmd.AddCommand(updateYamlCmd())

	releaseCmd.AddCommand(bundleCmd)

	bundleCmd.AddCommand(checkBundleCmd())
	bundleCmd.AddCommand(showBundleCommand())
	bundleCmd.AddCommand(bundleGitlabCmd())
	bundleCmd.AddCommand(bundleGithubCmd())
	bundleCmd.AddCommand(updateBundleYamlCmd())
}
