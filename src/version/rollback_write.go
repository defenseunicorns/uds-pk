// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"errors"
	"fmt"
	"os"
)

var writeFileInPlace = writeFilePreservingMetadata

type stagedUpdate struct {
	fileUpdate
	originalContent []byte
}

func readFileWithMode(path string) ([]byte, os.FileMode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}

	return data, info.Mode(), nil
}

func writeUpdatesWithRollback(updates []fileUpdate) error {
	staged := make([]stagedUpdate, 0, len(updates))
	for _, update := range updates {
		originalContent, _, err := readFileWithMode(update.path)
		if err != nil {
			return fmt.Errorf("backup %s: %w", update.label, err)
		}
		staged = append(staged, stagedUpdate{fileUpdate: update, originalContent: originalContent})
	}

	applied := 0
	for i := range staged {
		err := writeFileInPlace(staged[i].path, staged[i].content)
		if err != nil {
			restoreCurrentErr := writeFileInPlace(staged[i].path, staged[i].originalContent)
			rollbackErr := rollbackAppliedUpdates(staged[:applied])
			return errors.Join(
				fmt.Errorf("update %s: %w", staged[i].label, err),
				wrapRestoreError(staged[i].label, restoreCurrentErr),
				rollbackErr,
			)
		}
		applied++
	}

	return nil
}

func writeFilePreservingMetadata(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	if _, err := file.Write(data); err != nil {
		return err
	}

	return nil
}

func rollbackAppliedUpdates(updates []stagedUpdate) error {
	var errs []error
	for i := len(updates) - 1; i >= 0; i-- {
		if err := writeFileInPlace(updates[i].path, updates[i].originalContent); err != nil {
			errs = append(errs, fmt.Errorf("rollback %s: %w", updates[i].label, err))
		}
	}

	return errors.Join(errs...)
}

func wrapRestoreError(label string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("restore %s: %w", label, err)
}
