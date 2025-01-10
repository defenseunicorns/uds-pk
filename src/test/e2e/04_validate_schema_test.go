// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemaValidateCommand(t *testing.T) {
	// Create a sandbox directory for this test
	e2e.CreateSandboxDir(t)
	defer e2e.CleanupSandboxDir(t)

	// Source directory that contains the input files
	test := "04_validate_schema"
	sandboxDir := "src/test/sandbox"
	srcDir := filepath.Join("src/test/values_schemas", test)
	dir := filepath.Join(sandboxDir, test)

	// Copy the test files into the sandbox
	err := e2e.CopyDir(srcDir, filepath.Join(sandboxDir, test))
	require.NoError(t, err, "failed to copy test files into sandbox")
	stdout, stderr, err := e2e.UDSPK("schema", "validate", "-b", dir)
	require.NoError(t, err, stdout, stderr)

	require.Contains(t, stderr, "All schemas match.")
}

func TestSchemaValidateFailCommand(t *testing.T) {
	// Create a sandbox directory for this test
	e2e.CreateSandboxDir(t)
	defer e2e.CleanupSandboxDir(t)

	// Source directory that contains the input files
	test := "04_validate_schema_fail"
	sandboxDir := "src/test/sandbox"
	srcDir := filepath.Join("src/test/values_schemas", test)
	dir := filepath.Join(sandboxDir, test)

	// Copy the test files into the sandbox
	err := e2e.CopyDir(srcDir, filepath.Join(sandboxDir, test))
	require.NoError(t, err, "failed to copy test files into sandbox")
	stdout, stderr, err := e2e.UDSPK("schema", "validate", "-b", dir)
	require.NoError(t, err, stdout, stderr)
	require.Contains(t, stderr, "Schema differences found.")
}
