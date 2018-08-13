package util

import (
	"github.com/DharmaOfCode/tenago/api"
)

type ResultTable struct {
	Rows			[][]string
	Columns			[]string
}

type Configuration struct {
	Credentials		Credential
}

type Credential struct{
	AccessKey 	string
	SecretKey	string
}

type AuditedAsset struct{
	Asset				api.Asset
	Tags				[]string
	Vulnerabilities[]   api.Vulnerability
	TotalRiskScore		float64
}

