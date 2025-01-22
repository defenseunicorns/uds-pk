// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"bytes"
	"strings"

	"github.com/mikefarah/yq/v4/pkg/yqlib"
	glog "gopkg.in/op/go-logging.v1"
)

func init() {
	glog.SetLevel(glog.WARNING, "yq-lib") //yq-lib is very verbose on the logging by default
}

func EvaluateYqToString(expr string, files ...string) (string, error) {
	buffer := new(bytes.Buffer)
	yamlPrefs := yqlib.YamlPreferences{}

	evaluator := yqlib.NewAllAtOnceEvaluator()
	encoder := yqlib.NewYamlEncoder(yamlPrefs)
	printWriter := yqlib.NewSinglePrinterWriter(buffer)
	printer := yqlib.NewPrinter(encoder, printWriter)
	decoder := yqlib.NewYamlDecoder(yamlPrefs)

	if err := evaluator.EvaluateFiles(expr, files, printer, decoder); err != nil {
		return "", err
	}
	return strings.TrimSpace(buffer.String()), nil
}
