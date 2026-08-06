// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package version

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var renameFile = os.Rename

type stagedUpdate struct {
	fileUpdate
	tempPath   string
	backupPath string
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

func writeUpdatesAtomically(updates []fileUpdate) error {
	staged := make([]stagedUpdate, 0, len(updates))
	for _, update := range updates {
		tempPath, err := writeTempFile(update)
		if err != nil {
			cleanupStagedFiles(staged)
			return fmt.Errorf("stage %s: %w", update.label, err)
		}
		staged = append(staged, stagedUpdate{fileUpdate: update, tempPath: tempPath})
	}

	applied := 0
	for i := range staged {
		backupPath, err := moveToBackup(staged[i].path)
		if err != nil {
			cleanupStagedFiles(staged[applied:])
			rollbackErr := rollbackAppliedUpdates(staged[:applied])
			if rollbackErr != nil {
				return errors.Join(fmt.Errorf("backup %s: %w", staged[i].label, err), rollbackErr)
			}
			return fmt.Errorf("backup %s: %w", staged[i].label, err)
		}
		staged[i].backupPath = backupPath

		err = renameFile(staged[i].tempPath, staged[i].path)
		if err != nil {
			restoreErr := renameFile(staged[i].backupPath, staged[i].path)
			cleanupErr := cleanupStagedFiles(staged[i:])
			rollbackErr := rollbackAppliedUpdates(staged[:applied])
			return errors.Join(
				fmt.Errorf("update %s: %w", staged[i].label, err),
				restoreErr,
				cleanupErr,
				rollbackErr,
			)
		}
		staged[i].tempPath = ""
		applied++
	}

	return cleanupBackupFiles(staged)
}

func writeTempFile(update fileUpdate) (string, error) {
	dir := filepath.Dir(update.path)
	pattern := filepath.Base(update.path) + ".tmp-*"
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	tempPath := file.Name()
	defer func() {
		_ = file.Close()
	}()

	if _, err := file.Write(update.content); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	if err := file.Chmod(update.mode); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}

	return tempPath, nil
}

func moveToBackup(path string) (string, error) {
	dir := filepath.Dir(path)
	pattern := filepath.Base(path) + ".bak-*"
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	backupPath := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(backupPath)
		return "", err
	}
	if err := os.Remove(backupPath); err != nil {
		return "", err
	}
	if err := renameFile(path, backupPath); err != nil {
		return "", err
	}

	return backupPath, nil
}

func rollbackAppliedUpdates(updates []stagedUpdate) error {
	var errs []error
	for i := len(updates) - 1; i >= 0; i-- {
		if updates[i].backupPath == "" {
			continue
		}
		if err := renameFile(updates[i].backupPath, updates[i].path); err != nil {
			errs = append(errs, fmt.Errorf("rollback %s: %w", updates[i].label, err))
			continue
		}
		updates[i].backupPath = ""
	}

	return errors.Join(errs...)
}

func cleanupBackupFiles(updates []stagedUpdate) error {
	var errs []error
	for _, update := range updates {
		if update.backupPath == "" {
			continue
		}
		if err := os.Remove(update.backupPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("cleanup backup %s: %w", update.label, err))
		}
	}

	return errors.Join(errs...)
}

func cleanupStagedFiles(updates []stagedUpdate) error {
	var errs []error
	for _, update := range updates {
		if update.tempPath == "" {
			continue
		}
		if err := os.Remove(update.tempPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("cleanup staged %s: %w", update.label, err))
		}
	}

	return errors.Join(errs...)
}
