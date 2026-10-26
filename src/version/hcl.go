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
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

func prepareNextBundleUpdate(flavor types.Flavor, releaseDir, packageName string, allowMissingBundle bool) (*fileUpdate, error) {
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
	if err := resolveLocals(body, evalContext); err != nil {
		return nil, fmt.Errorf("evaluate bundle %s: %w", bundlePath, err)
	}

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
		if strings.Contains(candidate, "://") {
			continue
		}
		arch, ok, err := sourceArchitecture(filename, packageName)
		if err != nil {
			return nil, fmt.Errorf("bundle %s: %w", bundlePath, err)
		}
		if !ok {
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
	versionAttr := metadata.Body.Attributes["version"]
	if versionAttr == nil {
		return nil, fmt.Errorf("bundle %s has no metadata.version", bundlePath)
	}
	if sourceAttr == nil {
		if allowMissingBundle {
			return nil, nil
		}
		return nil, fmt.Errorf("bundle %s has no local source for Zarf package %q", bundlePath, packageName)
	}
	sourceRange := sourceAttr.Expr.Range()

	// Use the evaluated filename only to locate the version. Preserve the original
	// template so architecture-dependent locals and directories stay dynamic.
	filename := path.Base(source)
	tag := utils.JoinNonEmpty("-", flavor.Version, flavor.Name)
	versionStart := len(source) - len(filename) + len(prefix) + len(sourceArch) + 1
	newSource, err := replaceSourceVersion(data, sourceAttr.Expr, evalContext, versionStart, tag)
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", bundlePath, err)
	}

	type replacement struct {
		start, end int
		text       string
	}
	versionRange := versionAttr.Expr.Range()
	replacements := []replacement{
		{versionRange.Start.Byte, versionRange.End.Byte, strconv.Quote(tag)},
		{sourceRange.Start.Byte, sourceRange.End.Byte, newSource},
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

func replaceSourceVersion(data []byte, expr hclsyntax.Expression, ctx *hcl.EvalContext, versionStart int, tag string) (string, error) {
	template, ok := expr.(*hclsyntax.TemplateExpr)
	if ok {
		offset := 0
		for _, part := range template.Parts {
			value, diags := part.Value(ctx)
			if diags.HasErrors() {
				break
			}
			value, err := convert.Convert(value, cty.String)
			if err != nil || !value.IsKnown() || value.IsNull() {
				break
			}
			text := value.AsString()
			if versionStart >= offset && versionStart <= offset+len(text) {
				if _, literal := part.(*hclsyntax.LiteralValueExpr); !literal {
					break
				}
				// Keep earlier expressions verbatim and encode the remaining literal
				// as HCL, including escapes for literal ${ and %{ sequences.
				prefix := data[expr.Range().Start.Byte:part.Range().Start.Byte]
				suffix := hclwrite.TokensForValue(cty.StringVal(text[:versionStart-offset] + tag + ".tar.zst")).Bytes()
				return string(prefix) + string(suffix[1:]), nil
			}
			offset += len(text)
		}
	}
	return "", fmt.Errorf("cannot safely replace source version at %s: version must start in a literal template segment", expr.Range())
}

func resolveLocals(body *hclsyntax.Body, ctx *hcl.EvalContext) error {
	locals := map[string]*hclsyntax.Attribute{}
	for _, block := range body.Blocks {
		if block.Type != "locals" {
			continue
		}
		for name, attr := range block.Body.Attributes {
			if _, exists := locals[name]; exists {
				return fmt.Errorf("duplicate local %q", name)
			}
			locals[name] = attr
		}
	}

	// Resolve only source dependencies. Other locals may use UDS CLI functions
	// such as file(), which this version updater does not need to evaluate.
	var needed []string
	addReferences := func(expr hclsyntax.Expression) {
		for _, traversal := range expr.Variables() {
			if traversal.RootName() != "local" {
				continue
			}
			if len(traversal) > 1 {
				if attr, ok := traversal[1].(hcl.TraverseAttr); ok {
					needed = append(needed, attr.Name)
					continue
				}
				if index, ok := traversal[1].(hcl.TraverseIndex); ok && index.Key.Type() == cty.String {
					needed = append(needed, index.Key.AsString())
					continue
				}
			}
			// A reference to the whole local object can select any local.
			for name := range locals {
				needed = append(needed, name)
			}
		}
	}
	for _, block := range body.Blocks {
		if block.Type == "package" {
			if source := block.Body.Attributes["source"]; source != nil {
				addReferences(source.Expr)
			}
		}
	}
	pending := map[string]*hclsyntax.Attribute{}
	for len(needed) > 0 {
		name := needed[0]
		needed = needed[1:]
		if attr, exists := locals[name]; exists && pending[name] == nil {
			pending[name] = attr
			addReferences(attr.Expr)
		}
	}
	values := map[string]cty.Value{}
	for len(pending) > 0 {
		ctx.Variables["local"] = cty.ObjectVal(values)
		progressed := false

		for name, attr := range pending {
			value, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() || !value.IsWhollyKnown() {
				continue
			}
			values[name] = value
			delete(pending, name)
			progressed = true
		}
		if !progressed {
			names := make([]string, 0, len(pending))
			for name := range pending {
				names = append(names, name)
			}
			sort.Strings(names)
			return fmt.Errorf("cannot resolve locals: %s", strings.Join(names, ", "))
		}
	}
	ctx.Variables["local"] = cty.ObjectVal(values)
	return nil
}

func sourceArchitecture(filename, packageName string) (arch string, ok bool, err error) {
	if !strings.HasSuffix(filename, ".tar.zst") {
		return "", false, nil
	}
	rest, ok := strings.CutPrefix(strings.TrimSuffix(filename, ".tar.zst"), "zarf-package-"+packageName+"-")
	if !ok {
		return "", false, nil
	}
	for _, arch := range []string{"${sys.arch}", "amd64", "arm64"} {
		if version, ok := strings.CutPrefix(rest, arch+"-"); ok && version != "" {
			// Labels may be aliases. Reject filenames with multiple possible
			// package/architecture/version boundaries instead of trusting a label.
			name := strings.TrimSuffix(strings.TrimPrefix(filename, "zarf-package-"), ".tar.zst")
			parts := strings.Split(name, "-")
			boundaries := 0
			for i := 1; i < len(parts)-1; i++ {
				switch parts[i] {
				case "${sys.arch}", "amd64", "arm64":
					boundaries++
				}
			}
			if boundaries > 1 {
				return "", false, fmt.Errorf("ambiguous Zarf archive %q for package %q", filename, packageName)
			}
			return arch, true, nil
		}
	}
	return "", false, nil
}
