// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

// Package zarf reads package source definitions without coupling callers to a wire schema.
package zarf

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/zarf-dev/zarf/src/api/v1alpha1"
	"github.com/zarf-dev/zarf/src/api/v1beta1"
)

type Metadata struct {
	Name         string `yaml:"name"`
	Version      string `yaml:"version"`
	Architecture string `yaml:"architecture"`
}

type Definition struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Variant    struct {
		Flavor       string `yaml:"flavor"`
		Architecture string `yaml:"architecture"`
	} `yaml:"variant"`
}

func (d Definition) IsComponent() bool { return d.Kind == string(v1beta1.ZarfComponentConfig) }

type Image struct {
	Name    string
	Source  string
	Archive string
}

type Component struct {
	Name         string
	Flavor       string
	Architecture string
	Images       []Image
	HasImports   bool
}

type Package struct {
	APIVersion string
	Metadata   Metadata
	Components []Component
}

type document struct {
	file   *ast.File
	target *ast.File
	prefix string
	header Definition
}

// parseDocument handles authoring sources, not the multi-document definitions in built packages.
func parseDocument(data []byte) (*document, error) {
	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	contentIndex := -1
	for i, candidate := range file.Docs {
		if candidate.Body == nil {
			continue
		}
		switch candidate.Body.Type() {
		case ast.CommentType, ast.CommentGroupType, ast.DirectiveType:
			continue
		}
		if contentIndex != -1 {
			return nil, fmt.Errorf("expected a single Zarf package source document")
		}
		contentIndex = i
	}
	if contentIndex == -1 {
		return nil, fmt.Errorf("expected a single Zarf package source document")
	}
	content := file.Docs[contentIndex]
	doc := &document{file: file, target: &ast.File{Docs: []*ast.DocumentNode{content}}}
	if content.Start != nil {
		// Keep the original preamble: the AST printer drops comments attached to directives.
		lines := strings.SplitAfter(string(data), "\n")
		doc.prefix = strings.Join(lines[:content.Start.Position.Line-1], "")
	}
	file.Docs = file.Docs[contentIndex:]
	if err := yaml.NodeToValue(file.Docs[0].Body, &doc.header); err != nil {
		return nil, err
	}
	if doc.header.APIVersion == "" {
		doc.header.APIVersion = v1alpha1.APIVersion
	}
	switch doc.header.APIVersion {
	case v1alpha1.APIVersion, v1beta1.APIVersion:
	default:
		return nil, fmt.Errorf("unsupported Zarf apiVersion %q", doc.header.APIVersion)
	}
	switch doc.header.Kind {
	case "":
		doc.header.Kind = "ZarfPackageConfig"
	case "ZarfPackageConfig", "ZarfInitConfig":
	case "ZarfComponentConfig":
		if doc.header.APIVersion != v1beta1.APIVersion {
			return nil, fmt.Errorf("component configs require apiVersion %s", v1beta1.APIVersion)
		}
	default:
		return nil, fmt.Errorf("unsupported Zarf package kind %q", doc.header.Kind)
	}
	if doc.header.Metadata.Name == "" {
		return nil, fmt.Errorf("zarf package metadata.name is required")
	}
	return doc, nil
}

// ReadDefinition reads release metadata for packages and standalone component configs.
func ReadDefinition(data []byte) (Definition, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return Definition{}, err
	}
	return doc.header, nil
}

// ReadMetadata reads only the header; beta-only and future fields are left untouched.
func ReadMetadata(data []byte) (Metadata, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return Metadata{}, err
	}
	return doc.header.Metadata, nil
}

func ReadFile(path string) (Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Package{}, err
	}
	pkg, err := Parse(data)
	if err != nil {
		return Package{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return pkg, nil
}

// Parse decodes native wire types with goccy, which honors their JSON tags and embedded fields.
// This deliberately does not resolve component imports or render package templates.
func Parse(data []byte) (Package, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return Package{}, err
	}
	if doc.header.IsComponent() {
		return Package{}, fmt.Errorf("component configs are not supported for package scanning")
	}
	pkg := Package{APIVersion: doc.header.APIVersion, Metadata: doc.header.Metadata}
	if pkg.APIVersion == v1beta1.APIVersion {
		var native v1beta1.Package
		if err := yaml.NodeToValue(doc.file.Docs[0].Body, &native); err != nil {
			return Package{}, err
		}
		for _, c := range native.Components {
			component := Component{Name: c.Name, Flavor: c.Selector.Flavor, Architecture: c.Selector.Architecture,
				HasImports: len(c.Import.Local) > 0 || len(c.Import.Remote) > 0}
			for _, image := range c.Images {
				source := string(image.Source)
				if source == "" {
					source = "registry"
				}
				component.Images = append(component.Images, Image{Name: image.Name, Source: source})
			}
			for _, archive := range c.ImageArchives {
				for _, image := range archive.Images {
					component.Images = append(component.Images, Image{Name: image.Name, Source: "archive", Archive: archive.Path})
				}
			}
			pkg.Components = append(pkg.Components, component)
		}
	} else {
		var native v1alpha1.ZarfPackage
		if err := yaml.NodeToValue(doc.file.Docs[0].Body, &native); err != nil {
			return Package{}, err
		}
		for _, c := range native.Components {
			component := Component{Name: c.Name, Flavor: c.Only.Flavor, Architecture: c.Only.Cluster.Architecture,
				HasImports: c.Import.Path != "" || c.Import.URL != ""}
			for _, image := range c.Images {
				component.Images = append(component.Images, Image{Name: image, Source: "registry"})
			}
			for _, archive := range c.ImageArchives {
				for _, image := range archive.Images {
					component.Images = append(component.Images, Image{Name: image, Source: "archive", Archive: archive.Path})
				}
			}
			pkg.Components = append(pkg.Components, component)
		}
	}
	return pkg, nil
}

// Flavors returns the declared flavors, or one empty flavor for an unflavored package.
func (p Package) Flavors() []string {
	set := map[string]bool{}
	for _, c := range p.Components {
		if c.Flavor != "" {
			set[c.Flavor] = true
		}
	}
	if len(set) == 0 {
		return []string{""}
	}
	flavors := make([]string, 0, len(set))
	for flavor := range set {
		flavors = append(flavors, flavor)
	}
	sort.Strings(flavors)
	return flavors
}

// RegistryImages combines shared and flavor-specific components, without silently skipping sources.
// Architecture selectors are unioned unless the package declares a target architecture.
func (p Package) RegistryImages() (map[string][]string, error) {
	result := map[string][]string{}
	for _, flavor := range p.Flavors() {
		seen := map[string]bool{}
		result[flavor] = []string{}
		for _, c := range p.Components {
			if c.Flavor != "" && c.Flavor != flavor {
				continue
			}
			if p.Metadata.Architecture != "" && c.Architecture != "" && c.Architecture != p.Metadata.Architecture {
				continue
			}
			if c.HasImports {
				return nil, fmt.Errorf("component %q imports other components; scan a resolved package source with imports inlined", c.Name)
			}
			for _, image := range c.Images {
				if image.Source != "registry" {
					return nil, fmt.Errorf("component %q image %q uses %s source; direct image scanning supports registry images only (scan the released package SBOM instead)", c.Name, image.Name, image.Source)
				}
				if image.Name == "" {
					return nil, fmt.Errorf("component %q contains an image without a name", c.Name)
				}
				if !seen[image.Name] {
					result[flavor] = append(result[flavor], image.Name)
					seen[image.Name] = true
				}
			}
		}
	}
	return result, nil
}

// UpdateVersion changes one metadata scalar, preserving the rest of the source document.
func UpdateVersion(data []byte, version string) ([]byte, string, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return nil, "", err
	}
	metadataPath, err := yaml.PathString("$.metadata")
	if err != nil {
		return nil, "", err
	}
	metadata, err := metadataPath.FilterFile(doc.target)
	if err != nil {
		return nil, "", err
	}
	metadataMap, ok := metadata.(*ast.MappingNode)
	if !ok {
		switch metadata.(type) {
		case *ast.AnchorNode, *ast.AliasNode:
			return updateResolvedVersion(doc, version)
		}
		return nil, "", fmt.Errorf("metadata must be a mapping to update its version")
	}
	if err := expandMetadataMerges(doc, metadataMap, metadataPath); err != nil {
		return nil, "", err
	}
	versionPath, err := yaml.PathString("$.metadata.version")
	if err != nil {
		return nil, "", err
	}
	// Marshal a string scalar so numeric-looking and special versions stay strings.
	encoded, err := yaml.Marshal(version)
	if err != nil {
		return nil, "", err
	}
	if strings.ContainsAny(version, "\r\n") {
		encoded = []byte(strconv.Quote(version))
	}
	if current, err := versionPath.FilterFile(doc.target); err == nil {
		if _, ok := current.(*ast.AnchorNode); ok {
			return updateResolvedVersion(doc, version)
		}
		replacement, err := parser.ParseBytes(encoded, parser.ParseComments)
		if err != nil {
			return nil, "", err
		}
		value := replacement.Docs[0].Body
		if err := value.SetComment(current.GetComment()); err != nil {
			return nil, "", err
		}
		err = versionPath.ReplaceWithNode(doc.target, value)
		if err != nil {
			return nil, "", err
		}
	} else if err := metadataPath.MergeFromReader(doc.target, strings.NewReader("version: "+string(encoded))); err != nil {
		return nil, "", err
	}
	out := []byte(doc.prefix + doc.file.String())
	checked, err := parseDocument(out)
	if err != nil {
		return nil, "", fmt.Errorf("validate updated Zarf source: %w", err)
	}
	// Zarf's schema validation first decodes YAML to a map. A typed metadata decode alone
	// misses merge/explicit-key collisions, so check the same strict generic decoding path.
	var values map[string]any
	if err := yaml.NodeToValue(checked.target.Docs[0].Body, &values); err != nil {
		return nil, "", fmt.Errorf("validate updated Zarf source: %w", err)
	}
	return out, doc.header.Metadata.Name, nil
}

// Materialize anchors when the updated target defines one, preserving the old
// values at every alias instead of changing them or leaving dangling references.
// This compatibility path reserializes the source, as the native updater did.
func updateResolvedVersion(doc *document, version string) ([]byte, string, error) {
	var root map[string]any
	if err := yaml.NodeToValue(doc.target.Docs[0].Body, &root); err != nil {
		return nil, "", err
	}
	metadata, ok := root["metadata"].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("metadata must be a mapping to update its version")
	}
	metadata = maps.Clone(metadata)
	metadata["version"] = version
	root["metadata"] = metadata
	out, err := yaml.Marshal(root)
	if err != nil {
		return nil, "", err
	}
	prefix := doc.prefix
	if doc.target.Docs[0].Start != nil {
		prefix += "---\n"
	}
	return append([]byte(prefix), out...), doc.header.Metadata.Name, nil
}

// Expand only metadata's inherited fields. Updating a shared anchor would also change
// unrelated aliases; adding an override leaves duplicate keys for Zarf's pinned decoder.
func expandMetadataMerges(doc *document, metadata *ast.MappingNode, path *yaml.Path) error {
	hasMerge := false
	for _, entry := range metadata.Values {
		hasMerge = hasMerge || entry.Key.IsMergeKey()
	}
	if !hasMerge {
		return nil
	}
	var root map[string]any
	if err := yaml.NodeToValue(doc.target.Docs[0].Body, &root); err != nil {
		return err
	}
	inherited, ok := root["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("merged metadata must be a mapping")
	}
	var explicit []*ast.MappingValueNode
	comments := metadata.GetComment()
	for _, entry := range metadata.Values {
		if entry.Key.IsMergeKey() {
			for _, node := range ast.Filter(ast.CommentType, entry) {
				if comments == nil {
					comments = &ast.CommentGroupNode{BaseNode: &ast.BaseNode{}}
				}
				switch comment := node.(type) {
				case *ast.CommentNode:
					comments.Comments = append(comments.Comments, comment)
				case *ast.CommentGroupNode:
					comments.Comments = append(comments.Comments, comment.Comments...)
				}
			}
			continue
		}
		var key string
		if err := yaml.NodeToValue(entry.Key, &key); err != nil {
			return err
		}
		delete(inherited, key)
		explicit = append(explicit, entry)
	}
	data, err := yaml.Marshal(inherited)
	if err != nil {
		return err
	}
	metadata.Values = explicit
	if err := metadata.SetComment(comments); err != nil {
		return err
	}
	return path.MergeFromReader(doc.target, bytes.NewReader(data))
}
