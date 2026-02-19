// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/compare"
	"github.com/defenseunicorns/uds-pk/src/scan"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/google/go-github/v73/github"
	"github.com/spf13/cobra"
	"github.com/zarf-dev/zarf/src/api/v1alpha1"
	"go.yaml.in/yaml/v4"
	"golang.org/x/oauth2"
)

// CommandRunner interface for better testability

// command options
type CompareOptions struct {
	AllowDifferentImages bool
}

type ImageFetchingOptions struct {
	PublicPackagesPrefix  string
	PrivatePackagesPrefix string
	RepoOwner             string
}

type CommonScanOptions struct {
	OutputDirectory  string
	DevNoCleanUp     bool
	ZarfYamlLocation string
	ExecCommand      utils.RunProcess
}

type ScanReleasedOptions struct {
	Scan  CommonScanOptions
	Fetch ImageFetchingOptions
}

type ScanZarfYamlOptions struct {
	Scan CommonScanOptions
}

type ScanAndCompareOptions struct {
	Scan                     ScanReleasedOptions
	Compare                  CompareOptions
	ScanAndCompareOutputFile string
	ImageNameOverrides       []string
}

// helper structs
type PackageWithVersion struct {
	encodedPackageUrl string
	versions          []*github.PackageVersion
}

func scanReleasedCmd() *cobra.Command {
	options := &ScanReleasedOptions{}
	cmd := &cobra.Command{
		Use:   "last-released",
		Short: "Scan a released version of a UDS package for vulnerabilities. The scan is based on SBOMs from the latest released version of the package.",
		RunE:  options.run,
	}
	addCommonFlags(cmd, &options.Scan)
	addScanReleasedFlags(cmd, options)

	return cmd
}

func (options *ScanReleasedOptions) run(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	log := Logger(&ctx)
	verbose := Verbose(&ctx)
	if options.Scan.OutputDirectory == "" {
		var err error
		options.Scan.OutputDirectory, err = os.MkdirTemp("", "releaseScans")
		log.Info("Output directory", slog.String("dir", options.Scan.OutputDirectory))
		if err != nil {
			return err
		}
	}
	_, err := ScanReleased(&ctx, options.Scan.OutputDirectory, options, log, verbose)
	return err
}

func scanZarfYamlCmd() *cobra.Command {
	options := ScanZarfYamlOptions{}
	cmd := &cobra.Command{
		Use:   "images",
		Short: "Scan the current Zarf package. This scan is based on the zarf.yaml and the current images it points to.",
		RunE:  options.run,
	}
	addCommonFlags(cmd, &options.Scan)

	return cmd
}

func (options *ScanZarfYamlOptions) run(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	log := Logger(&ctx)
	verbose := Verbose(&ctx)
	outputDirectory := options.Scan.OutputDirectory
	if outputDirectory == "" {
		var err error
		outputDirectory, err = os.MkdirTemp("", "zarfScans")
		log.Info("Output directory", slog.String("dir", outputDirectory))
		if err != nil {
			return err
		}
	}
	_, err := ScanZarfYamlImages(outputDirectory, &options.Scan, log, verbose)
	return err
}

func compareCmd() *cobra.Command {
	options := CompareOptions{}
	cmd := &cobra.Command{
		Use:   "compare-scans BASE_SCAN NEW_SCAN",
		Short: "Compare two grype scans using the cyclonedx-json output format",
		Args:  cobra.ExactArgs(2),
		RunE:  options.run,
	}
	addCompareFlags(cmd, &options)
	return cmd
}

func addCompareFlags(cmd *cobra.Command, options *CompareOptions) {
	cmd.Flags().BoolVarP(&options.AllowDifferentImages, "allow-different-images", "d", false, "Allow comparing scans for different images")
}

func (options *CompareOptions) run(_ *cobra.Command, args []string) error {
	baseScanPath := args[0]
	newScanPath := args[1]
	markdownTable, err := compareScans(baseScanPath, newScanPath, options)
	if err != nil {
		return err
	}

	fmt.Println(markdownTable)
	return nil
}

func compareScans(baseScanPath string, newScanPath string, options *CompareOptions) (string, error) {
	baseScan, newScan, err := compare.LoadScans(baseScanPath, newScanPath)
	if err != nil {
		return "", err
	}

	baseScan.Metadata.Component.Name = compare.TrimDockerRegistryPrefixes(baseScan.Metadata.Component.Name)
	newScan.Metadata.Component.Name = compare.TrimDockerRegistryPrefixes(newScan.Metadata.Component.Name)

	if baseScan.Metadata.Component.Name != newScan.Metadata.Component.Name {
		if !options.AllowDifferentImages {
			return "", fmt.Errorf("these scans are not for the same image: %s != %s", baseScan.Metadata.Component.Name, newScan.Metadata.Component.Name)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: these scans are not for the same image: %s != %s\n", baseScan.Metadata.Component.Name, newScan.Metadata.Component.Name)
		}
	}

	vulnStatus := compare.GenerateComparisonMap(baseScan, newScan)

	return compare.GenerateComparisonMarkdown(baseScan, newScan, vulnStatus)
}

func scanAndCompareCmd() *cobra.Command {
	options := ScanAndCompareOptions{}

	cmd := &cobra.Command{
		Use: "compare",
		Short: "Scan the current Zarf package, scan the last released package, and compare the scans." +
			"This command is a combination of `scan`, `scan-released`, and `compare-scans`.",
		RunE: options.Run,
	}
	addCommonFlags(cmd, &options.Scan.Scan)
	addScanReleasedFlags(cmd, &options.Scan)
	addCompareFlags(cmd, &options.Compare)
	cmd.Flags().StringArrayVar(&options.ImageNameOverrides, "image-name-override", []string{}, "Override image name mapping for comparison (format: old=new). Can be repeated.")
	return cmd
}

func (options *ScanAndCompareOptions) Run(cmd *cobra.Command, _ []string) error { //exposed for tests
	ctx := cmd.Context()
	log := Logger(&ctx)
	verbose := Verbose(&ctx)
	outputDirectory := options.Scan.Scan.OutputDirectory
	if outputDirectory == "" {
		var err error
		outputDirectory, err = os.MkdirTemp("", "scans")
		if err != nil {
			return err
		}
		log.Info("Output directory", slog.String("dir", outputDirectory))
	}
	zarfYamlScanOutDir := path.Join(outputDirectory, "zarfYaml")
	log.Debug("Scanning zarf.yaml images")
	zarfYamlScanResults, err := ScanZarfYamlImages(zarfYamlScanOutDir, &options.Scan.Scan, log, verbose)
	if err != nil {
		return err
	}

	releasedScanOutDir := path.Join(outputDirectory, "released")
	releasedScanResults, err := ScanReleased(&ctx, releasedScanOutDir, &options.Scan, log, verbose)
	if err != nil {
		return err
	}
	log.Debug("Comparing scans", slog.Any("current", zarfYamlScanResults), slog.Any("released", releasedScanResults))

	var builder strings.Builder

	for flavor, flavorResults := range zarfYamlScanResults {
		log.Debug("Scanning flavor", slog.String("flavor", flavor))
		releasedFlavorResults, found := releasedScanResults[flavor]
		if !found {
			log.Warn("No released scan results found for flavor", slog.String("flavor", flavor))
			continue // TODO: present scanning results for the flavor that has been added?
		}
		for key, scanFile := range flavorResults {
			imageName := extractImageName(key)
			for _, override := range options.ImageNameOverrides {
				parts := strings.SplitN(override, "=", 2)
				if len(parts) == 2 && parts[1] == imageName {
					imageName = parts[0]
					log.Debug("Found override image name for image", slog.String("image", key), slog.String("override", imageName))
					break
				}
			}
			releasedScanFile, found := findMatchingScan(imageName, releasedFlavorResults, log)
			if !found {
				fmt.Fprintf(&builder, "### %s: No released scan found for image\n", imageName)
				builder.WriteString("This is likely a new image\n")
				// aligning with how it worked in callable-scan, we print all the vulnerabilities as existing ones
				// for images that are newly added
				releasedScanFile = scanFile
			}
			log.Debug("Comparing files: ", slog.String("base", releasedScanFile), slog.String("new", scanFile))
			markdownTable, err := compareScans(releasedScanFile, scanFile, &options.Compare)
			if err != nil {
				return err
			}
			if options.ScanAndCompareOutputFile != "" {
				if builder.Len() > 0 {
					builder.WriteString("\n\n")
				}
				builder.WriteString(markdownTable)
			} else {
				fmt.Println(markdownTable)
			}
		}
	}
	if options.ScanAndCompareOutputFile != "" {
		if dir := filepath.Dir(options.ScanAndCompareOutputFile); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		if err := os.WriteFile(options.ScanAndCompareOutputFile, []byte(builder.String()), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func extractImageName(imageURL string) string {
	// Remove the scheme prefix if present
	imageURL = strings.TrimPrefix(imageURL, "registry:")
	imageURL = strings.TrimPrefix(imageURL, "docker:")
	// Remove the tag (after the colon)
	imagePath := imageURL
	if idx := strings.LastIndex(imageURL, ":"); idx != -1 {
		imagePath = imageURL[:idx]
	}
	// Get the last segment (image name)
	return filepath.Base(imagePath)
}

func findMatchingScan(imageName string, releasedResults map[string]string, logger *slog.Logger) (string, bool) {
	for _, scanFile := range releasedResults {
		if strings.Contains(scanFile, "/"+imageName+"_") {
			return scanFile, true
		}
	}
	return "", false
}

func ScanZarfYamlImages(zarfYamlScanOutDir string, options *CommonScanOptions, log *slog.Logger, verbose bool) (map[string]map[string]string, error) {
	scanImagesResult := make(map[string]map[string]string)
	pkg, err1 := parseZarfYaml(options)
	if err1 != nil {
		return scanImagesResult, err1
	}
	pkgName := pkg.Metadata.Name
	log.Debug("Package name", slog.String("pkgName", pkgName))
	tempDir, err := os.MkdirTemp("", "images")
	if err != nil {
		return scanImagesResult, err
	}

	if !options.DevNoCleanUp {
		defer os.RemoveAll(tempDir) //nolint:errcheck
	}

	log.Debug("Temporary directory", slog.String("dir", tempDir))
	flavorToImages := getImages(&pkg)
	for flavor, images := range flavorToImages {
		targetFlavorDir := path.Join(zarfYamlScanOutDir, flavor)
		// TODO: cache image fetching and scanning so that we don't redo this on duplicates
		scanImagesResult[flavor], err = scan.Images(images, targetFlavorDir, log, verbose, options.ExecCommand)
		if err != nil {
			return scanImagesResult, err
		}
	}

	log.Info("Successfully scanned images used in the package.")
	return scanImagesResult, nil
}

func ScanReleased(ctx *context.Context, outDirectory string, options *ScanReleasedOptions, log *slog.Logger, verbose bool) (map[string]map[string]string, error) {
	log.Debug("Scan command invoked", slog.String("zarfLocation", options.Scan.ZarfYamlLocation))
	pkg, err1 := parseZarfYaml(&options.Scan)
	sbomScanResults := make(map[string]map[string]string)
	if err1 != nil {
		return sbomScanResults, err1
	}
	pkgName := pkg.Metadata.Name
	log.Debug("Package name", slog.String("pkgName", pkgName))
	publicRepoUrl, err3 := determineRepositoryUrl(pkgName, options.Fetch.RepoOwner, options.Fetch.PublicPackagesPrefix, "packages/uds", log)
	if err3 != nil {
		return sbomScanResults, err3
	}
	encodedPublicUrl := url.PathEscape(publicRepoUrl)

	privateRepoUrl, err4 := determineRepositoryUrl(pkgName, options.Fetch.RepoOwner, options.Fetch.PrivatePackagesPrefix, "packages/private/uds", log)
	if err4 != nil {
		return sbomScanResults, err4
	}
	encodedPrivateUrl := url.PathEscape(privateRepoUrl)

	client := NewGithubClient(ctx)

	var packageUrls []string
	if exists, err := checkPackageExistenceInRepo(client, ctx, options.Fetch.RepoOwner, encodedPublicUrl, log); err != nil {
		return sbomScanResults, fmt.Errorf("failed to check package existence for URL: %s, %w", encodedPublicUrl, err)
	} else if exists {
		log.Debug("Package exists in public repo, adding it to fetch", slog.String("packageUrl", publicRepoUrl))
		packageUrls = append(packageUrls, publicRepoUrl)
	}
	if exists, err := checkPackageExistenceInRepo(client, ctx, options.Fetch.RepoOwner, encodedPrivateUrl, log); err != nil {
		return sbomScanResults, fmt.Errorf("failed to check package existence for URL: %s, %w", encodedPrivateUrl, err)
	} else if exists {
		log.Debug("Package exists in private repo, adding it to fetch", slog.String("packageUrl", privateRepoUrl))
		packageUrls = append(packageUrls, privateRepoUrl)
	}

	// create a temporary directory dropped after the program finishes:
	tempDir, err := os.MkdirTemp("", "sboms")
	log.Debug("Temporary directory", slog.String("dir", tempDir))
	if err != nil {
		return sbomScanResults, err
	}

	if !options.Scan.DevNoCleanUp {
		defer os.RemoveAll(tempDir) //nolint:errcheck
	}

	flavors := determineFlavors(&pkg)
	log.Debug("Flavors", slog.Any("flavors", flavors))

	flavorToSboms, err := fetchSbomsForFlavors(ctx, client, packageUrls, flavors, options.Fetch.RepoOwner, tempDir, log)
	if err != nil {
		return sbomScanResults, err
	}

	log.Debug("Would analyze SBOMs for vulnerabilities", slog.Any("sboms", flavorToSboms))

	targetSbomsDir := path.Join(tempDir, "targetSboms")
	if err := os.Mkdir(targetSbomsDir, 0755); err != nil {
		return sbomScanResults, err
	}

	// move flavor jsons to a single directory:
	for flavor, sboms := range flavorToSboms {
		targetFlavorDir := path.Join(targetSbomsDir, flavor)
		if err := os.Mkdir(targetFlavorDir, 0755); err != nil {
			return sbomScanResults, err
		}
		for _, sbom := range sboms {
			// Get the base name of the file (e.g., "foo.txt")
			fileName := filepath.Base(sbom)

			// Join to get the target file path
			targetPath := filepath.Join(targetFlavorDir, fileName)

			// Move the file (rename works across directories in most cases)
			if err := os.Rename(sbom, targetPath); err != nil {
				return sbomScanResults, err
			}
		}
		outputDir := path.Join(outDirectory, flavor) + string(os.PathSeparator)
		resultFiles, err := scan.SBOMs(targetFlavorDir, outputDir, log, verbose, options.Scan.ExecCommand)
		if err != nil {
			return sbomScanResults, err
		}
		sbomScanResults[flavor] = resultFiles
	}

	log.Info("Successfully scanned SBOMs for a released version of the package.")

	return sbomScanResults, nil
}

// NewGithubClient exposed for testing purposes
var NewGithubClient = createGithubClient
var FetchSboms = utils.FetchSboms

func getAuthToken() string {
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken != "" {
		return githubToken
	}
	return os.Getenv("GITLAB_RELEASE_TOKEN")
}

func createGithubClient(ctx *context.Context) *github.Client {
	log := Logger(ctx)
	// GitHub REST API requires raw token, not base64-encoded
	token := getAuthToken()
	if token == "" {
		log.Warn("No GitHub token found in environment (GITHUB_TOKEN or GITLAB_RELEASE_TOKEN)")
	} else {
		log.Debug("GitHub token found for REST API", slog.Int("length", len(token)))
	}
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(*ctx, ts)
	return github.NewClient(tc)
}

func fetchSbomsForFlavors(ctx *context.Context, client *github.Client,
	packageUrls []string, flavors []string, repoOwner string, tempDir string,
	log *slog.Logger) (map[string][]string, error) {
	flavorToSboms := map[string][]string{}

	var packagesWithVersions []PackageWithVersion
	for _, packageUrl := range packageUrls {
		encodedPackageUrl := url.PathEscape(packageUrl)
		log.Debug("Package url", slog.String("packageUrl", packageUrl), slog.String("encodedPackageUrl", encodedPackageUrl))
		versions, _, err := client.Organizations.PackageGetAllVersions(
			*ctx,
			repoOwner,
			"container",
			packageUrl,
			&github.PackageListOptions{},
		)
		if err != nil {
			log.Debug("failed to get package versions: ", slog.Any("error", err))
		}
		packagesWithVersions = append(packagesWithVersions, PackageWithVersion{
			encodedPackageUrl: encodedPackageUrl,
			versions:          versions,
		})
	}

	for _, flavor := range flavors {
		tag, packageUrl, err := findNewestTagForFlavor(packagesWithVersions, flavor, log)
		if err != nil {
			return flavorToSboms, err
		}
		sboms, err := fetchSboms(tempDir, tag, repoOwner, packageUrl, log)
		if err != nil {
			return flavorToSboms, err
		}
		flavorToSboms[flavor] = sboms
	}

	return flavorToSboms, nil
}

func findNewestTagForFlavor(versions []PackageWithVersion, flavor string, log *slog.Logger) (string, string, error) {
	for _, packageWithVersion := range versions {
		packageUrl := packageWithVersion.encodedPackageUrl
		versions := packageWithVersion.versions
		for _, version := range versions {
			var metadataMap map[string]interface{}
			if err := json.Unmarshal(version.Metadata, &metadataMap); err == nil {
				if container, ok := metadataMap["container"].(map[string]interface{}); ok {
					if tags, ok := container["tags"].([]interface{}); ok {
						// select the newest tag:
						for _, tRaw := range tags {
							if tag, ok := tRaw.(string); ok {
								if strings.HasSuffix(tag, flavor) {
									log.Debug("Found tag", slog.String("tag", tag))
									return tag, packageUrl, nil
								}
							}
						}
					}
				}
			}
		}
	}
	log.Warn("No tags found for flavor", slog.String("flavor", flavor))
	return "", "", nil
}

func fetchSboms(tempDir string, tag string, repoOwner string, packageUrl string, log *slog.Logger) ([]string, error) {
	subDir, dirCreationErr := os.MkdirTemp(tempDir, tag)
	if dirCreationErr != nil {
		return nil, dirCreationErr
	}
	if sboms, err := FetchSboms(repoOwner, packageUrl, tag, subDir, log); err != nil {
		log.Debug("Error inspecting sbom", slog.Any("error", err))
		return nil, err
	} else {
		log.Debug("Sboms", slog.Any("sboms", sboms))
		return sboms, nil
	}
}

func checkPackageExistenceInRepo(client *github.Client, ctx *context.Context, owner string, pkgUrl string, log *slog.Logger) (bool, error) {
	log.Debug("Checking if package exists", slog.String("url", pkgUrl), slog.String("owner", owner))
	apiPath := fmt.Sprintf("/orgs/%s/packages/container/%s", owner, pkgUrl)
	req, err := client.NewRequest("GET", apiPath, nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(*ctx, req, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			log.Debug("Package not found", slog.String("url", pkgUrl))
			return false, nil
		}
		return false, err
	}
	defer resp.Body.Close() //nolint:errcheck
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

func determineRepositoryUrl(pkgName string, repoOwner string, prefix string, path string, log *slog.Logger) (string, error) {
	const defenseUnicorns = "defenseunicorns"
	log.Debug("Determining repository URL", slog.String("pkgName", pkgName),
		slog.String("repoOwner", repoOwner), slog.String("prefix", prefix), slog.String("path", path))
	if repoOwner == defenseUnicorns {
		return fmt.Sprintf("%s/%s", path, pkgName), nil
	}
	if prefix == "" {
		return pkgName, nil
	}
	return fmt.Sprintf("%s/%s", prefix, pkgName), nil
}

func parseZarfYaml(options *CommonScanOptions) (v1alpha1.ZarfPackage, error) {
	data, err := os.ReadFile(options.ZarfYamlLocation)
	if err != nil {
		return v1alpha1.ZarfPackage{}, err
	}
	var pkg v1alpha1.ZarfPackage
	if err := yaml.Unmarshal(data, &pkg); err != nil {
		return v1alpha1.ZarfPackage{}, err
	}
	return pkg, nil
}

func getImages(pkg *v1alpha1.ZarfPackage) map[string][]string {
	flavorToImages := make(map[string][]string)
	for _, component := range pkg.Components {
		if component.Only.Flavor != "" {
			flavorToImages[component.Only.Flavor] = component.Images
		}
	}

	return flavorToImages
}

func determineFlavors(pkg *v1alpha1.ZarfPackage) []string {
	flavorSet := map[string]bool{}
	for _, component := range pkg.Components {
		if component.Only.Flavor != "" {
			flavorSet[component.Only.Flavor] = true
		}
	}
	flavors := make([]string, 0, len(flavorSet))
	for flavor := range flavorSet {
		flavors = append(flavors, flavor)
	}
	return flavors
}

func init() {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Collection of commands for scanning packages",
	}
	scanCmd.AddCommand(scanReleasedCmd())
	scanCmd.AddCommand(scanZarfYamlCmd())
	scanCmd.AddCommand(scanAndCompareCmd())

	rootCmd.AddCommand(compareCmd())
	rootCmd.AddCommand(scanCmd)
}

func addScanReleasedFlags(cmd *cobra.Command, options *ScanReleasedOptions) {
	cmd.Flags().StringVarP(&options.Fetch.PublicPackagesPrefix, "public-packages-prefix", "c", "", "The prefix for public packages")
	cmd.Flags().StringVarP(&options.Fetch.PrivatePackagesPrefix, "private-packages-prefix", "r", "private", "The prefix for private packages")
	cmd.Flags().StringVarP(&options.Fetch.RepoOwner, "repo-owner", "w", "uds-packages", "Repository owner")
}

func addCommonFlags(cmd *cobra.Command, options *CommonScanOptions) {
	cmd.Flags().StringVarP(&options.ZarfYamlLocation, "zarf-yaml-path", "p", "./zarf.yaml", "Path to the zarf.yaml file")
	cmd.Flags().StringVarP(&options.OutputDirectory, "output-directory", "o", "", "Output directory")
	cmd.Flags().BoolVar(&options.DevNoCleanUp, "dev-no-cleanup", false, "For development: do not clean up temporary files")
	options.ExecCommand = utils.OsRunProcess
}
