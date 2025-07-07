// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package platforms

import (
	"fmt"
	"os"
	"testing"

	"github.com/defenseunicorns/uds-pk/src/types"
)

func TestVerifyEnvVar(t *testing.T) {
	tests := []struct {
		varName     string
		setVar      bool
		varContents string
		expectError bool
	}{
		{
			varName:     "TEST_VAR",
			setVar:      true,
			varContents: "test",
			expectError: false,
		},
		{
			varName:     "TEST_VAR",
			setVar:      false,
			varContents: "",
			expectError: true,
		},
		{
			varName:     "TEST_VAR",
			setVar:      true,
			varContents: "",
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("setVar: %t contents:%s", test.setVar, test.varContents), func(t *testing.T) {
			if test.setVar {
				os.Setenv(test.varName, test.varContents) // nolint:errcheck
				defer os.Unsetenv(test.varName)           // nolint:errcheck
			} else {
				os.Unsetenv(test.varName) // nolint:errcheck
			}

			err := VerifyEnvVar(test.varName)
			if test.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %s", err)
				}
			}
		})
	}
}

func TestReleaseExists(t *testing.T) {
	tests := []struct {
		expectedStatusCode int
		receivedStatusCode int
		err                error
		pattern            string
		packageName        string
		flavor             types.Flavor
		expectError        bool
	}{
		{
			expectedStatusCode: 409,
			receivedStatusCode: 200,
			err:                nil,
			pattern:            "already_exists",
			packageName:        "test",
			flavor:             types.Flavor{Name: "test", Version: "1.0"},
			expectError:        false,
		},
		{
			expectedStatusCode: 409,
			receivedStatusCode: 409,
			err:                fmt.Errorf("message: already_exists"),
			pattern:            "already_exists",
			packageName:        "test",
			flavor:             types.Flavor{Name: "test", Version: "1.0"},
			expectError:        false,
		},
		{
			expectedStatusCode: 409,
			receivedStatusCode: 409,
			err:                fmt.Errorf("message: other error"),
			pattern:            "already_exists",
			packageName:        "test",
			flavor:             types.Flavor{Name: "test", Version: "1.0"},
			expectError:        true,
		},
		{
			expectedStatusCode: 409,
			receivedStatusCode: 411,
			err:                fmt.Errorf("message: other error"),
			pattern:            "already_exists",
			packageName:        "test",
			flavor:             types.Flavor{Name: "test", Version: "1.0"},
			expectError:        true,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("expectedCode: %d receivedCode: %d error: %v", test.expectedStatusCode, test.receivedStatusCode, test.err), func(t *testing.T) {
			err := ReleaseExists(test.expectedStatusCode, test.receivedStatusCode, test.err, test.pattern, test.packageName, test.flavor)
			if test.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %s", err)
				}
			}
		})
	}
}
