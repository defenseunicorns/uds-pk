// Copyright 2024-2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseunicorns/uds-pk/src/types"
	"github.com/defenseunicorns/uds-pk/src/utils"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

func prepareNextBundleUpdate(flavor types.Flavor, releaseDir, packageName string) (*fileUpdate, error) {
	bundlePath := filepath.Join(releaseDir, "bundle", "bundle.uds.hcl")
	data, mode, err := readFileWithMode(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("read bundle %s: %w", bundlePath, err)
	}

	parsed, diags := hclsyntax.ParseConfig(data, bundlePath, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse bundle %s: %s", bundlePath, diags.Error())
	}

	body := parsed.Body.(*hclsyntax.Body)
	var metadata *hclsyntax.Block
	var sourceAttr *hclsyntax.Attribute
	var source string
	var sourceArch string
	prefix := "zarf-package-" + packageName + "-"
	evalContext := &hcl.EvalContext{Variables: map[string]cty.Value{
		"sys": cty.ObjectVal(map[string]cty.Value{
			"arch": cty.StringVal("${sys.arch}"),
		}),
	}}
	for _, block := range body.Blocks {
		if block.Type == "metadata" {
			metadata = block
		}
		if block.Type != "package" {
			continue
		}
		attr := block.Body.Attributes["source"]
		if attr == nil {
			continue
		}
		r := attr.Expr.Range()
		literal := string(data[r.Start.Byte:r.End.Byte])
		if len(literal) < 2 || literal[0] != '"' {
			continue
		}
		value, diags := attr.Expr.Value(evalContext)
		if diags.HasErrors() || !value.IsKnown() || value.IsNull() || value.Type() != cty.String {
			continue
		}
		candidate := value.AsString()
		filename := path.Base(candidate)
		if strings.Contains(candidate, "://") || !strings.HasPrefix(filename, prefix) || !strings.HasSuffix(filename, ".tar.zst") {
			continue
		}
		nameAndVersion := strings.TrimSuffix(strings.TrimPrefix(filename, "zarf-package-"), ".tar.zst")
		best := -1
		var arch, oldVersion string
		for _, candidateArch := range []string{"${sys.arch}", "amd64", "arm64"} {
			marker := "-" + candidateArch + "-"
			if i := strings.LastIndex(nameAndVersion, marker); i > best {
				best = i
				arch = candidateArch
				oldVersion = nameAndVersion[i+len(marker):]
			}
		}
		if best < 0 || nameAndVersion[:best] != packageName || oldVersion == "" {
			continue
		}
		if sourceAttr != nil {
			return nil, fmt.Errorf("bundle %s has multiple sources for Zarf package %q", bundlePath, packageName)
		}
		sourceAttr, source, sourceArch = attr, candidate, arch
	}
	if metadata == nil {
		return nil, fmt.Errorf("bundle %s has no metadata block", bundlePath)
	}
	if sourceAttr == nil {
		return nil, fmt.Errorf("bundle %s has no local source for Zarf package %q", bundlePath, packageName)
	}

	versionAttr := metadata.Body.Attributes["version"]
	if versionAttr == nil {
		return nil, fmt.Errorf("bundle %s has no metadata.version", bundlePath)
	}
	sourceRange := sourceAttr.Expr.Range()

	// Keep the directory and architecture placeholder; replace only the version.
	filename := path.Base(source)

	tag := utils.JoinNonEmpty("-", flavor.Version, flavor.Name)
	newFilename := prefix + sourceArch + "-" + tag + ".tar.zst"
	newSource := strings.TrimSuffix(source, filename) + newFilename

	type replacement struct {
		start, end int
		text       string
	}
	versionRange := versionAttr.Expr.Range()
	replacements := []replacement{
		{versionRange.Start.Byte, versionRange.End.Byte, strconv.Quote(tag)},
		{sourceRange.Start.Byte, sourceRange.End.Byte, strconv.Quote(newSource)},
	}
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].start > replacements[j].start
	})

	updated := string(data)
	for _, change := range replacements {
		updated = updated[:change.start] + change.text + updated[change.end:]
	}

	return &fileUpdate{
		path:    bundlePath,
		label:   "bundle.uds.hcl",
		version: tag,
		content: []byte(updated),
		mode:    mode,
	}, nil
}
