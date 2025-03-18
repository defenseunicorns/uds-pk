// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/defenseunicorns/uds-pk/src/types"
	goyaml "github.com/goccy/go-yaml"
	syaml "sigs.k8s.io/yaml"
)

func LoadReleaseConfig(dir string) (types.ReleaseConfig, error) {

	var config types.ReleaseConfig
	err := LoadYaml(filepath.Join(dir, "/releaser.yaml"), &config)
	if err != nil {
		return types.ReleaseConfig{}, err
	}

	return config, nil
}

func LoadYaml(path string, destVar interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return goyaml.Unmarshal(data, destVar)
}

func UpdateYaml(path string, srcVar interface{}) error {
	data, err := goyaml.Marshal(srcVar)
	if err != nil {
		return err
	}

	yamlInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, yamlInfo.Mode())
}

// converts interface to yaml
func ToYaml(v interface{}) (string, error) {
	b, err := syaml.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// renderTemplate reads the file at filePath, registers custom functions,
// and executes the template with the provided data.
func RenderTemplate(filePath string, data interface{}) ([]byte, error) {
	tmpl, err := template.New(filepath.Base(filePath)).Funcs(template.FuncMap{
		"toYaml":  ToYaml,
		"nindent": Nindent,
	}).ParseFiles(filePath)
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}
	return buf.Bytes(), nil
}
