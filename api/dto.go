package api

import "encoding/json"

//https://cloud.tenable.com/api#/resources/assets
type Asset struct {
	Id 			        string   `json:"id"`
	BIOSUUID 			string   `json:"bios_uuid"`
	IPv4List 			[]string `json:"ipv4"`
	IPv6List 			[]string `json:"ipv6"`
	HostnameList 		[]string `json:"ipv6"`
	SSHFingerprint		string 	 `json:"ssh_fingerprint"`
	FQDNList			[]string `json:"fqdn"`
	MACAddressesList	[]string `"json:mac_address"`
	NetbiosName     	[]string `json:"netbios_name"`
	OS              	[]string `json:"operating_system"`
	SystemType      	string   `json:"system_type"`
}

type AssetInfo struct {
	Id 			   			string   				`json:"id"`
	Tags					[]string 				`json:"tags"`
	VulnerabilitiesCount	VulnerabilitiesCount	`json:"counts"`
}

type AssetsList struct {
	Assets[] Asset	`json:"assets"`
}

type TargetGroup struct {
	Id  	json.Number `json:"id"`
	Type	string   	`json:"type"`
	Members	string 	 	`json:"members"`
	Name	string 	 	`json:"name"`
}

type TargetGroupsList struct {
	TargetGroups[] 	TargetGroup	`json:"target_groups"`
}

type AssetVulnerabilitiesList struct {
	Vulnerabilities[]	AssetVulnerability	`json:"vulnerabilities"`
}

type AssetVulnerability struct {
	Count 				json.Number 					`json:"count"`
	PluginFamily		string   						`json:"plugin_family"`
	PluginId			json.Number 					`json:"plugin_id"`
	PluginName			string   						`json:"plugin_name"`
	VulnerabilityState	string							`json:"vulnerability_state"`
	AcceptedCount		json.Number 					`json:"accepted_count"`
	RecastedCount		json.Number 					`json:"recasted_count"`
	CountsBySeverity[]	VulnerabilityCountsBySeverity	`json:"counts_by_severity"`
	Severity			json.Number 					`json:"severity"`
}

type VulnerabilityCountsBySeverity struct {
	Count 	json.Number `json:"count"`
	Value 	json.Number `json:"value"`
}

type VulnerabilitiesCount struct {
	Total 		json.Number 	`json:"total"`
	Severities	[]SeverityCount `json:"severities"`
}

type SeverityCount struct {
	Count 	json.Number `json:"count"`
	Level	json.Number `json:"level"`
	Name 	string 		`json:"name"`
}

type VulnerabilityInfo struct {
	Count 			json.Number 	`json:"count"`
	Description 	string 			`json:"description"`
	Synopsis 		string 			`json:"synopsis"`
	Solution 		string 			`json:"solution"`
	RiskInformation RiskInformation `json:"risk_information"`
}

type AssetVulnerabilityInfo struct {
	Info 	VulnerabilityInfo  `json:"info"`
}

type RiskInformation struct {
	RiskFactor			string 		`json:"risk_factor"`
	CVSSVector			string 		`json:"cvss_vector"`
	CVSSBaseScore		string 		`json:"cvss_base_score"`
	CVSSTemporalVector	string 		`json:"cvss_temporal_vector"`
	CVSSTemporalScore	json.Number `json:"cvss_temporal_score"`
	CVSS3Vector			string 		`json:"s_temporal_score"`
	CVSS3BaseScore		string 		`json:"cvss3_base_score"`
	CVSS3TemporalVector	string 		`json:"cvss3_temporal_vector"`
	CVSS3TemporalScore	string 		`json:"cvss3_temporal_score"`
	StigSeverity		string 		`json:"stig_severity"`
}
