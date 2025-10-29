// Copyright 2025 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"io"
	"os/exec"
)

type CommandRunner interface {
	Run() error
	SetStdout(stdout io.Writer)
	SetStderr(stderr io.Writer)
	CombinedOutput() ([]byte, error)
}

type RunProcess func(name string, arg ...string) CommandRunner

type RealCommand struct {
	cmd *exec.Cmd
}

func (r *RealCommand) Run() error {
	return r.cmd.Run()
}

func (r *RealCommand) SetStdout(stdout io.Writer) {
	r.cmd.Stdout = stdout
}

func (r *RealCommand) SetStderr(stderr io.Writer) {
	r.cmd.Stderr = stderr
}

func (r *RealCommand) CombinedOutput() ([]byte, error) {
	return r.cmd.CombinedOutput()
}

// Update ExecCommand to use CommandRunner
var OsRunProcess RunProcess = func(name string, arg ...string) CommandRunner {
	return &RealCommand{cmd: exec.Command(name, arg...)}
}
