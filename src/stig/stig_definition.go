// Copyright 2026 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

import "fmt"

var stigDefinitions = map[string]STIGDefinition{
	ASDSTIGProfileKey: {
		ID:             ASDSTIGProfileKey,
		Revision:       "v6r4",
		ChecklistSlug:  "asd",
		TargetRole:     "Application Server",
		TechnologyArea: "Application Review",
		STIGName:       "Application Security and Development Security Technical Implementation Guide",
		DisplayName:    "Application Security and Development",
		STIGID:         "Application_Security_Development_STIG",
		ZipURL:         "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R4_STIG.zip",
		XCCDFName:      "U_ASD_STIG_V6R4_Manual-xccdf.xml",
	},
	RHEL9STIGProfileKey: {
		ID:             RHEL9STIGProfileKey,
		Revision:       "v2r7",
		ChecklistSlug:  "rhel9",
		TargetRole:     "Operating System",
		TechnologyArea: "Operating System Review",
		STIGName:       "Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
		DisplayName:    "Red Hat Enterprise Linux 9",
		STIGID:         "RHEL_9_STIG",
		ZipURL:         "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R7_STIG.zip",
		XCCDFName:      "U_RHEL_9_STIG_V2R7_Manual-xccdf.xml",
	},
}

func LookupSTIGDefinition(id string) (STIGDefinition, error) {
	definition, ok := stigDefinitions[id]
	if !ok {
		return STIGDefinition{}, fmt.Errorf("unsupported STIG %q", id)
	}
	return definition, nil
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
