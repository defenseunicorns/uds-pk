// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
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

var zarfYamlLocation string
var publicPackagesPrefix string
var privatePackagesPrefix string
var devNoCleanUp bool
var repoOwner string

var outputDirectory string

var allowDifferentImages bool
var imageNameOverrides []string

// Optional output file for scan-and-compare markdown
var scanAndCompareOutputFile string

var scanReleasedCmd = &cobra.Command{
	Use:   "scan-released",
	Short: "Scan a released version of a UDS package for vulnerabilities. The scan is based on SBOMs from the latest released version of the package.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if outputDirectory == "" {
			var err error
			outputDirectory, err = os.MkdirTemp("", "releaseScans")
			logger.Info("Output directory", slog.String("dir", outputDirectory))
			if err != nil {
				return err
			}
		}
		_, err := scanReleased(outputDirectory)
		return err
	},
}

var scanZarfYamlCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan the current Zarf package. This scan is based on the zarf.yaml and the current images it points to.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if outputDirectory == "" {
			var err error
			outputDirectory, err = os.MkdirTemp("", "zarfScans")
			logger.Info("Output directory", slog.String("dir", outputDirectory))
			if err != nil {
				return err
			}
		}
		_, err := scanZarfYamlImages(outputDirectory)
		return err
	},
}

var compareCmd = &cobra.Command{
	Use:   "compare-scans BASE_SCAN NEW_SCAN",
	Short: "Compare two grype scans using the cyclonedx-json output format",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		baseScanPath := args[0]
		newScanPath := args[1]
		markdownTable, err := compareScans(baseScanPath, newScanPath)
		if err != nil {
			return err
		}

		fmt.Println(markdownTable)
		return nil
	},
}

func compareScans(baseScanPath string, newScanPath string) (string, error) {
	baseScan, newScan, err := compare.LoadScans(baseScanPath, newScanPath)
	if err != nil {
		return "", err
	}

	baseScan.Metadata.Component.Name = compare.TrimDockerRegistryPrefixes(baseScan.Metadata.Component.Name)
	newScan.Metadata.Component.Name = compare.TrimDockerRegistryPrefixes(newScan.Metadata.Component.Name)

	if baseScan.Metadata.Component.Name != newScan.Metadata.Component.Name {
		if !allowDifferentImages {
			return "", fmt.Errorf("these scans are not for the same image: %s != %s", baseScan.Metadata.Component.Name, newScan.Metadata.Component.Name)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: these scans are not for the same image: %s != %s\n", baseScan.Metadata.Component.Name, newScan.Metadata.Component.Name)
		}
	}

	vulnStatus := compare.GenerateComparisonMap(baseScan, newScan)

	markdownTable, err := compare.GenerateComparisonMarkdown(baseScan, newScan, vulnStatus)
	if err != nil {
		return "", err
	}
	return markdownTable, nil
}

var scanAndCompareCmd = &cobra.Command{
	Use: "scan-and-compare",
	Short: "Scan the current Zarf package, scan the last released package, and compare the scans." +
		"This command is a combination of `scan`, `scan-released`, and `compare-scans`.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if outputDirectory == "" {
			var err error
			outputDirectory, err = os.MkdirTemp("", "scans")
			logger.Info("Output directory", slog.String("dir", outputDirectory))
			if err != nil {
				return err
			}
		}
		zarfYamlScanOutDir := outputDirectory + string(os.PathSeparator) + "zarfYaml"
		logger.Debug("Scanning zarf.yaml images")
		zarfYamlScanResults, err := scanZarfYamlImages(zarfYamlScanOutDir)
		if err != nil {
			return err
		}

		releasedScanOutDir := outputDirectory + string(os.PathSeparator) + "released"
		releasedScanResults, err := scanReleased(releasedScanOutDir)
		if err != nil {
			return err
		}
		logger.Debug("Comparing scans", slog.Any("current", zarfYamlScanResults), slog.Any("released", releasedScanResults))

		var builder strings.Builder

		for flavor, flavorResults := range zarfYamlScanResults {
			logger.Debug("Scanning flavor", slog.String("flavor", flavor))
			if releasedFlavorResults, found := releasedScanResults[flavor]; found {
				for key, scanFile := range flavorResults {
					imageName := extractImageName(key)
					for _, override := range imageNameOverrides {
						parts := strings.SplitN(override, "=", 2)
						if len(parts) == 2 && parts[1] == imageName {
							imageName = parts[0]
							logger.Debug("Found override image name for image", slog.String("image", key), slog.String("override", imageName))
							break
						}
					}
					if releasedScanFile, err := findMatchingScan(imageName, releasedFlavorResults, logger); err != nil {
						return err
					} else {
						logger.Debug("Comparing files: ", slog.String("base", releasedScanFile), slog.String("new", scanFile))
						markdownTable, err := compareScans(releasedScanFile, scanFile)
						if err != nil {
							return err
						}
						if scanAndCompareOutputFile != "" {
							if builder.Len() > 0 {
								builder.WriteString("\n\n")
							}
							builder.WriteString(markdownTable)
						} else {
							fmt.Println(markdownTable)
						}
					}
				}
			}
		}
		if scanAndCompareOutputFile != "" {
			// Ensure parent directory exists if provided
			if dir := filepath.Dir(scanAndCompareOutputFile); dir != "." && dir != "" {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
			}
			if err := os.WriteFile(scanAndCompareOutputFile, []byte(builder.String()), 0o644); err != nil {
				return err
			}
		}
		return nil
	},
}

func extractImageName(imageURL string) string {
	// Remove the "docker:" prefix if present
	imageURL = strings.TrimPrefix(imageURL, "docker:")
	// Remove the tag (after the colon)
	imagePath := imageURL
	if idx := strings.LastIndex(imageURL, ":"); idx != -1 {
		imagePath = imageURL[:idx]
	}
	// Get the last segment (image name)
	return filepath.Base(imagePath)
}

func findMatchingScan(imageName string, releasedResults map[string]string, logger *slog.Logger) (string, error) {
	for _, scanFile := range releasedResults {
		if strings.Contains(scanFile, "/"+imageName+"_") {
			return scanFile, nil
		} else {
			logger.Debug("no matchy-matchy", slog.String("imageName", imageName), slog.String("scanFile", scanFile))
		}
	}
	return "", fmt.Errorf("could not find matching scan for %s", imageName)
}

func scanZarfYamlImages(zarfYamlScanOutDir string) (map[string]map[string]string, error) {
	scanImagesResult := make(map[string]map[string]string)
	pkg, err1 := parseZarfYaml()
	if err1 != nil {
		return scanImagesResult, err1
	}
	pkgName, err2 := determinePackageName(&pkg)
	logger.Debug("Package name", slog.String("pkgName", pkgName))
	if err2 != nil {
		return scanImagesResult, err2
	}
	tempDir, err := os.MkdirTemp("", "images")
	if err != nil {
		return scanImagesResult, err
	}

	if !devNoCleanUp {
		defer func(path string) {
			_ = os.RemoveAll(path)
		}(tempDir) //nolint:errcheck // best effort cleanup
	}

	logger.Debug("Temporary directory", slog.String("dir", tempDir))
	flavorToImages := getImages(&pkg)
	for flavor, images := range flavorToImages {
		targetFlavorDir := zarfYamlScanOutDir + string(os.PathSeparator) + flavor
		// TODO: cache image fetching and scanning so that we don't redo this on duplicates
		scanImagesResult[flavor], err = scan.Images(images, targetFlavorDir, logger, verbose)
		if err != nil {
			return scanImagesResult, err
		}
	}

	logger.Info("Successfully scanned images used in the package.")
	return scanImagesResult, nil
}

func scanReleased(outDirectory string) (map[string]map[string]string, error) {
	logger.Debug("Scan command invoked", slog.String("zarfLocation", zarfYamlLocation))
	pkg, err1 := parseZarfYaml()
	sbomScanResults := make(map[string]map[string]string)
	if err1 != nil {
		return sbomScanResults, err1
	}
	pkgName, err2 := determinePackageName(&pkg)
	if err2 != nil {
		return sbomScanResults, err2
	}
	logger.Debug("Package name", slog.String("pkgName", pkgName))
	publicRepoUrl, err3 := determineRepositoryUrl(pkgName, repoOwner, publicPackagesPrefix, "packages/uds")
	if err3 != nil {
		return sbomScanResults, err3
	}
	encodedPublicUrl := encodePackageUrl(publicRepoUrl)

	privateRepoUrl, err4 := determineRepositoryUrl(pkgName, repoOwner, privatePackagesPrefix, "packages/private/uds")
	if err4 != nil {
		return sbomScanResults, err4
	}
	encodedPrivateUrl := encodePackageUrl(privateRepoUrl)

	ctx := context.Background()
	client := NewGithubClient(&ctx)

	var packageUrls []string
	if exists, err := checkPackageExistenceInRepo(client, &ctx, repoOwner, encodedPublicUrl); err != nil {
		return sbomScanResults, fmt.Errorf("failed to check package existence for URL: %s, %w", encodedPublicUrl, err)
	} else if exists {
		logger.Debug("Package exists in public repo, adding it to fetch", slog.String("packageUrl", publicRepoUrl))
		packageUrls = append(packageUrls, publicRepoUrl)
	}
	if exists, err := checkPackageExistenceInRepo(client, &ctx, repoOwner, encodedPrivateUrl); err != nil {
		return sbomScanResults, fmt.Errorf("failed to check package existence for URL: %s, %w", encodedPrivateUrl, err)
	} else if exists {
		logger.Debug("Package exists in private repo, adding it to fetch", slog.String("packageUrl", privateRepoUrl))
		packageUrls = append(packageUrls, privateRepoUrl)
	}

	// create a temporary directory dropped after the program finishes:
	tempDir, err := os.MkdirTemp("", "sboms")
	logger.Debug("Temporary directory", slog.String("dir", tempDir))
	if err != nil {
		return sbomScanResults, err
	}

	if !devNoCleanUp {
		defer func(path string) {
			_ = os.RemoveAll(path) // best effort cleanup
		}(tempDir)
	}

	flavors := determineFlavors(&pkg)
	logger.Debug("Flavors", slog.Any("flavors", flavors))

	flavorToSboms, err := fetchSbomsForFlavors(&ctx, client, packageUrls, flavors, tempDir)
	if err != nil {
		return sbomScanResults, err
	}

	logger.Debug("Would analyze SBOMs for vulnerabilities", slog.Any("sboms", flavorToSboms))

	targetSbomsDir := tempDir + string(os.PathSeparator) + "targetSboms"
	if err := os.Mkdir(targetSbomsDir, 0755); err != nil {
		return sbomScanResults, err
	}

	// move flavor jsons to a single directory:
	for flavor, sboms := range flavorToSboms {
		targetFlavorDir := targetSbomsDir + string(os.PathSeparator) + flavor
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
		outputDir := outDirectory + string(os.PathSeparator) + flavor + string(os.PathSeparator)
		resultFiles, err := scan.SBOMs(targetFlavorDir, outputDir, logger, verbose)
		if err != nil {
			return sbomScanResults, err
		}
		sbomScanResults[flavor] = resultFiles
	}

	logger.Info("Successfully scanned SBOMs for a released version of the package.")

	return sbomScanResults, nil
}

// Seam variables for testability
var NewGithubClient = createGithubClient
var FetchSboms = utils.FetchSboms

func createGithubClient(ctx *context.Context) *github.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: utils.GetGithubToken()},
	)
	tc := oauth2.NewClient(*ctx, ts)
	return github.NewClient(tc)
}

func fetchSbomsForFlavors(ctx *context.Context, client *github.Client, packageUrls []string, flavors []string, tempDir string) (map[string][]string, error) {
	flavorToSboms := map[string][]string{}

	for _, packageUrl := range packageUrls {
		encodedPackageUrl := encodePackageUrl(packageUrl)
		logger.Debug("Package url", slog.String("packageUrl", packageUrl), slog.String("encodedPackageUrl", encodedPackageUrl))
		versions, _, err := client.Organizations.PackageGetAllVersions(
			*ctx,
			repoOwner,
			"container",
			packageUrl,
			&github.PackageListOptions{},
		)
		logger.Debug("Trying to get package versions for", slog.String("url", encodedPackageUrl))
		if err != nil {
			logger.Debug("failed to get package versions: ", slog.Any("error", err))
		} else {
			logger.Debug("package versions found for ", slog.String("url", encodedPackageUrl))
			for _, flavor := range flavors {
			versionsFor:
				for _, v := range versions {
					var metadataMap map[string]interface{}
					if err := json.Unmarshal(v.Metadata, &metadataMap); err == nil {
						if container, ok := metadataMap["container"].(map[string]interface{}); ok {
							if tags, ok := container["tags"].([]interface{}); ok {
								// select the newest tag:
								for _, tRaw := range tags {
									if tag, ok := tRaw.(string); ok {
										if strings.HasSuffix(tag, flavor) {
											subDir, dirCreationErr := os.MkdirTemp(tempDir, tag)
											if dirCreationErr != nil {
												return nil, dirCreationErr
											}
											if sboms, err := FetchSboms(repoOwner, packageUrl, tag, subDir, logger); err != nil {
												logger.Debug("Error inspecting sbom", slog.Any("error", err))
											} else {
												logger.Debug("Sboms", slog.Any("sboms", sboms))
												flavorToSboms[flavor] = sboms
											}
											break versionsFor
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return flavorToSboms, nil
}

func checkPackageExistenceInRepo(client *github.Client, ctx *context.Context, owner string, pkgUrl string) (bool, error) {
	logger.Debug("Checking if package %s exists in ", pkgUrl, owner)
	apiPath := fmt.Sprintf("/orgs/%s/packages/container/%s", owner, pkgUrl)
	req, err := client.NewRequest("GET", apiPath, nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(*ctx, req, nil)
	if err != nil {
		return false, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body) // best effort close

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

func encodePackageUrl(url string) string {
	// replace '/' with '%2F'
	encoded := strings.ReplaceAll(url, "/", "%2F")

	return encoded
}

func determineRepositoryUrl(pkgName string, repoOwner string, prefix string, path string) (string, error) {
	const defenseUnicorns = "defenseunicorns"
	logger.Debug("Determining repository URL", slog.String("pkgName", pkgName), slog.String("repoOwner", repoOwner), slog.String("prefix", prefix), slog.String("path", path))
	if repoOwner == defenseUnicorns {
		return fmt.Sprintf("%s/%s", path, pkgName), nil
	}
	if prefix == "" {
		return pkgName, nil
	}
	return fmt.Sprintf("%s/%s", prefix, pkgName), nil
}

func parseZarfYaml() (v1alpha1.ZarfPackage, error) {
	data, err := os.ReadFile(zarfYamlLocation)
	if err != nil {
		return v1alpha1.ZarfPackage{}, err
	}
	var pkg v1alpha1.ZarfPackage
	if err := yaml.Unmarshal(data, &pkg); err != nil {
		return v1alpha1.ZarfPackage{}, err
	}
	return pkg, nil
}

func determinePackageName(pkg *v1alpha1.ZarfPackage) (string, error) {
	packageName := pkg.Metadata.Name

	return packageName, nil
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
	addCommonFlags(scanReleasedCmd)
	scanReleasedCmd.Flags().StringVarP(&publicPackagesPrefix, "publicPackagesPrefix", "c", "", "The prefix for public packages")
	scanReleasedCmd.Flags().StringVarP(&privatePackagesPrefix, "privatePackagesPrefix", "r", "private", "The prefix for private packages")
	scanReleasedCmd.Flags().StringVarP(&repoOwner, "repoOwner", "w", "uds-packages", "Repository owner") // TODO: that okay?
	rootCmd.AddCommand(scanReleasedCmd)

	addCommonFlags(scanZarfYamlCmd)
	rootCmd.AddCommand(scanZarfYamlCmd)

	addCommonFlags(scanAndCompareCmd)
	scanAndCompareCmd.Flags().StringVarP(&publicPackagesPrefix, "publicPackagesPrefix", "c", "", "The prefix for public packages")
	scanAndCompareCmd.Flags().StringVarP(&privatePackagesPrefix, "privatePackagesPrefix", "r", "private", "The prefix for private packages")
	scanAndCompareCmd.Flags().StringVarP(&repoOwner, "repoOwner", "w", "uds-packages", "Repository owner") // TODO: that okay?
	scanAndCompareCmd.Flags().StringArrayVar(&imageNameOverrides, "image-name-override", []string{}, "Override image name mapping for comparison (format: old=new). Can be repeated.")
	scanAndCompareCmd.Flags().StringVar(&scanAndCompareOutputFile, "output", "", "Write comparison markdown to this file instead of stdout")

	scanAndCompareCmd.Flags().BoolVarP(&allowDifferentImages, "allow-different-images", "d", false, "Allow comparing scans for different images")
	rootCmd.AddCommand(scanAndCompareCmd)

	compareCmd.Flags().BoolVarP(&allowDifferentImages, "allow-different-images", "d", false, "Allow comparing scans for different images")
	rootCmd.AddCommand(compareCmd)
}

func addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&zarfYamlLocation, "zarfYamlPath", "p", "./zarf.yaml", "Path to the zarf.yaml file")
	cmd.Flags().StringVarP(&outputDirectory, "outputDirectory", "o", "", "Output directory")
	cmd.Flags().BoolVar(&devNoCleanUp, "devNoCleanUp", false, "For development: do not clean up temporary files")
}
