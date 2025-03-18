package utils

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/zarf-dev/zarf/src/pkg/message"
)

// atLeastOneExists evaluates a YAML query expression against a file and returns true if any result is found,
// or false along with an error if something goes wrong.
func AtLeastOneExists(expression string, file string) (bool, error) {
	result, err := EvaluateYqToString(expression, file)
	if err == nil {
		return len(result) > 0, nil
	}
	return false, nil
}

// getSliceOfValues runs a YAML query against a file, splits the resulting string by newline,
// and returns the values as a slice of strings.
func GetSliceOfValues(expression string, file string) ([]string, error) {
	result, err := EvaluateYqToString(expression, file)
	if err == nil {
		if len(result) > 0 {
			return strings.Split(result, "\n"), nil
		}
		return nil, nil
	}
	return nil, err
}

// fileExists checks whether a file exists at the specified path and ensures it is not a directory.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// dedupe removes duplicate strings from the provided slice and returns a slice containing only unique values.
func Dedupe(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, str := range input {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}
	return result
}

func Nindent(n int, s string) string {
	indent := ""
	for i := 0; i < n; i++ {
		indent += " "
	}
	lines := []string{}
	for _, line := range bytes.Split([]byte(s), []byte("\n")) {
		// Skip empty lines.
		if len(line) > 0 {
			lines = append(lines, indent+string(line))
		} else {
			lines = append(lines, "")
		}
	}
	return fmt.Sprint(lines)
}

// getNamespaces extracts namespace values from the common and root Zarf YAML files,
func GetNamespaces(commonZarfPath, rootZarfPath string) ([]string, error) {
	var namespaces []string

	processPath := func(path string) error {
		if FileExists(path) {
			values, err := GetSliceOfValues(".components[].charts[].namespace  | select(. != null)", path)
			if err != nil {
				message.Infof("Error reading namespaces from %s - %s", path, err)
				return err
			}
			if len(values) > 0 {
				namespaces = append(namespaces, values...)
			}
		}
		return nil
	}

	if err := processPath(commonZarfPath); err != nil {
		message.Infof("Continuing despite error with %s", commonZarfPath)
	}
	err := processPath(rootZarfPath)
	namespaces = Dedupe(namespaces)
	sort.Strings(namespaces)
	return namespaces, err
}
