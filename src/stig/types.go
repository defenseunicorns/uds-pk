// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package stig

// Profile represents the stig-profile.yaml configuration.
type Profile struct {
	AppName     string              `yaml:"app_name"`
	FQDN        string              `yaml:"fqdn"`
	Description string              `yaml:"description"`
	Chars       Characteristics     `yaml:"characteristics"`
	Platform    PlatformConfig      `yaml:"platform"`
	Overrides   map[string]Override `yaml:"overrides,omitempty"`
}

type Characteristics struct {
	UsesSOAP              bool   `yaml:"uses_soap"`
	UsesSAML              bool   `yaml:"uses_saml"`
	UsesXML               bool   `yaml:"uses_xml"`
	UsesDatabase          bool   `yaml:"uses_database"`
	UsesPasswords         bool   `yaml:"uses_passwords"`
	UsesPKI               bool   `yaml:"uses_pki_cac"`
	ProcessesClassified   bool   `yaml:"processes_classified_data"`
	ProcessesCUI          bool   `yaml:"processes_cui"`
	HasUserInput          bool   `yaml:"has_user_input"`
	HasAdminInterface     bool   `yaml:"has_admin_interface"`
	HasFileUpload         bool   `yaml:"has_file_upload"`
	IsStateless           bool   `yaml:"is_stateless"`
	HasMobileCode         bool   `yaml:"has_mobile_code"`
	IsHighAvailability    bool   `yaml:"is_high_availability"`
	IsPubliclyAccessible  bool   `yaml:"is_publicly_accessible"`
	HasWebServices        bool   `yaml:"has_web_services"`
	HasSharedAccounts     bool   `yaml:"has_shared_accounts"`
	HasNonLocalMaint      bool   `yaml:"has_non_local_maintenance"`
	DoesKeyExchange       bool   `yaml:"does_key_exchange"`
	IsTransactionBased    bool   `yaml:"is_transaction_based"`
	IsConfigMgmtApp       bool   `yaml:"is_config_mgmt_app"`
	AuthenticatesDevices  bool   `yaml:"authenticates_devices"`
	HasCryptoModuleAccess bool   `yaml:"has_crypto_module_access"`
	InDoDDMZ              bool   `yaml:"in_dod_dmz"`
	IsCritical            bool   `yaml:"is_critical"`
	HostsNonOrgUsers      bool   `yaml:"hosts_non_org_users"`
	DevelopedInHouse      bool   `yaml:"developed_in_house"`
	Language              string `yaml:"language"`
}

type PlatformConfig struct {
	AuthProvider       string `yaml:"auth_provider"`
	AuthProxy          string `yaml:"auth_proxy"`
	ServiceMesh        string `yaml:"service_mesh"`
	TLSProvider        string `yaml:"tls_provider"`
	ContainerRuntime   string `yaml:"container_runtime"`
	ContainerUser      string `yaml:"container_user"`
	BaseImage          string `yaml:"base_image"`
	NetworkPolicies    bool   `yaml:"network_policies"`
	CICD_SAST          string `yaml:"cicd_sast"`
	CICD_SecretsScan   string `yaml:"cicd_secrets_scan"`
	CICD_Signing       string `yaml:"cicd_signing"`
	DependencyMonitor  string `yaml:"dependency_monitoring"`
	SCM                string `yaml:"scm"`
	DefectTracking     string `yaml:"defect_tracking"`
	CentralizedLogging bool   `yaml:"centralized_logging"`
	ResourceLimits     string `yaml:"resource_limits"`
}

// Override allows per-rule status/finding overrides in the profile.
type Override struct {
	Status         string `yaml:"status"`
	FindingDetails string `yaml:"finding_details"`
	Comments       string `yaml:"comments,omitempty"`
}

// CKLB types matching the SV3 schema.

type Checklist struct {
	Title       string      `json:"title"`
	ID          string      `json:"id"`
	CKLBVersion string      `json:"cklb_version"`
	Active      bool        `json:"active"`
	Mode        int         `json:"mode"`
	HasPath     bool        `json:"has_path"`
	TargetData  *TargetData `json:"target_data"`
	STIGs       []STIG      `json:"stigs"`
}

type TargetData struct {
	TargetType     string `json:"target_type"`
	HostName       string `json:"host_name"`
	IPAddress      string `json:"ip_address"`
	MACAddress     string `json:"mac_address"`
	FQDN           string `json:"fqdn"`
	Comments       string `json:"comments"`
	Role           string `json:"role"`
	IsWebDatabase  bool   `json:"is_web_database"`
	TechnologyArea string `json:"technology_area"`
	WebDBSite      string `json:"web_db_site"`
	WebDBInstance  string `json:"web_db_instance"`
}

type STIG struct {
	STIGName            string  `json:"stig_name"`
	DisplayName         string  `json:"display_name"`
	STIGID              string  `json:"stig_id"`
	ReleaseInfo         string  `json:"release_info"`
	UUID                string  `json:"uuid"`
	ReferenceIdentifier *string `json:"reference_identifier"`
	Size                int     `json:"size"`
	Rules               []Rule  `json:"rules"`
}

type Rule struct {
	GroupIDSrc        string           `json:"group_id_src"`
	GroupTree         []GroupTreeEntry `json:"group_tree"`
	GroupID           string           `json:"group_id"`
	Severity          string           `json:"severity"`
	GroupTitle        string           `json:"group_title"`
	RuleIDSrc         string           `json:"rule_id_src"`
	RuleID            string           `json:"rule_id"`
	RuleVersion       string           `json:"rule_version"`
	RuleTitle         string           `json:"rule_title"`
	FixText           string           `json:"fix_text"`
	Weight            string           `json:"weight"`
	CheckContent      string           `json:"check_content"`
	CheckContentRef   *CheckContentRef `json:"check_content_ref"`
	Classification    string           `json:"classification"`
	Discussion        string           `json:"discussion"`
	FalsePositives    string           `json:"false_positives"`
	FalseNegatives    string           `json:"false_negatives"`
	Documentable      string           `json:"documentable"`
	SecurityOverride  string           `json:"security_override_guidance"`
	PotentialImpacts  string           `json:"potential_impacts"`
	ThirdPartyTools   string           `json:"third_party_tools"`
	IAControls        string           `json:"ia_controls"`
	Responsibility    string           `json:"responsibility"`
	Mitigations       string           `json:"mitigations"`
	MitigationControl string           `json:"mitigation_control"`
	LegacyIDs         []string         `json:"legacy_ids"`
	CCIs              []string         `json:"ccis"`
	ReferenceID       *string          `json:"reference_identifier"`
	UUID              string           `json:"uuid"`
	SIGUUID           string           `json:"stig_uuid"`
	Status            string           `json:"status"`
	Overrides         map[string]any   `json:"overrides"`
	Comments          string           `json:"comments"`
	FindingDetails    string           `json:"finding_details"`
}

type GroupTreeEntry struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type CheckContentRef struct {
	Href string `json:"href"`
	Name string `json:"name"`
}
