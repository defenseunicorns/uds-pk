// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init PACKAGE_NAME",
	Short: "Initialize a new UDS package from the official template",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		packageName := args[0]
		targetDir := filepath.Join(".", packageName)
		templateRepo := "https://github.com/uds-packages/template.git"

		// Clone the template repo
		if err := exec.Command("git", "clone", templateRepo, targetDir).Run(); err != nil {
			return fmt.Errorf("failed to clone template: %w", err)
		}

		// Remove .git directory
		if err := os.RemoveAll(filepath.Join(targetDir, ".git")); err != nil {
			return fmt.Errorf("failed to remove .git: %w", err)
		}

		// Update uds-package.yaml name field
		packageYaml := filepath.Join(targetDir, "uds-package.yaml")
		data, err := os.ReadFile(packageYaml)
		if err != nil {
			return fmt.Errorf("failed to read uds-package.yaml: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "name:") {
				lines[i] = "name: " + packageName
			}
		}
		if err := os.WriteFile(packageYaml, []byte(strings.Join(lines, "\n")), 0644); err != nil {
			return fmt.Errorf("failed to update uds-package.yaml: %w", err)
		}

		fmt.Printf("Initialized UDS package '%s' from template.\n", packageName)
		return nil
	},
}
