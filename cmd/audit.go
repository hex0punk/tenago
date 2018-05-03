package cmd

import (
	"github.com/spf13/cobra"
	"errors"
	"github.com/DharmaOfCode/tenago/util"
	"fmt"
	"log"
)

type AuditState struct {
	Assets		bool
	Vulns		bool
	Limit 		int
}

var (
	auditState AuditState

	auditCmd = &cobra.Command{
		Use:   "audit",
		Short: "Perform audit tasks on your servers and vulnerabilities.",
		Long:  `Perform audit tasks on your servers and vulnerabilities.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if !auditState.Assets && !auditState.Vulns{
				return errors.New("you need to tell me what to audit (vulnerabilities or assets)")
			}

			return nil
		},
		Run: runAudit,
	}
)

func init(){
	auditState = AuditState{}

	auditCmd.Flags().BoolVarP(&auditState.Assets, "Score assets", "A", false, "Score assets by custom risk")
	auditCmd.Flags().BoolVarP(&auditState.Vulns, "Score vulnerabilities", "V", false, "Score assets by custom risk")
	auditCmd.Flags().IntVarP(&auditState.Limit, "Limit output by number of results", "L", 100, "Limit")

	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string){
	valid := true
	if auditState.Assets && auditState.Vulns{
		fmt.Println("[!] You cannot combine -A and -V flags")
	}
	if !valid {
		util.PrintRuler(Verbose)
		errors.New("error running query command")
	} else {
		processAudit(&auditState)
	}
}

func processAudit(s *AuditState){
	var result *util.ResultTable

	if s.Assets{
		result = auditAssets(s)
	}

	if s.Vulns{
		auditVulns(s)
	}

	util.PrintResult(Verbose, result)
}

func auditAssets(s *AuditState) *util.ResultTable{
	//Get asset IDs
	assetsList, err := Client.ListAssets()
	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"Asset ID", "Score"}
	resultTable := util.ResultTable{
		Columns: columns,
	}

	for _, a :=  range assetsList.Assets {
		auditedAsset := util.AuditedAsset{Asset: a}
		auditedAsset.TotalRiskScore = 0
		assetInfo, err := Client.AssetInfo(a.Id)
		if err != nil {
			log.Fatal(err)
		}

		auditedAsset.Tags = assetInfo.Tags

		vulnerabilitiesList, err := Client.ListAssetVulnerabilities(a.Id)
		if err != nil {
			log.Fatal(err)
		}
		auditedAsset.Vulnerabilities = vulnerabilitiesList.Vulnerabilities

		for _, v := range auditedAsset.Vulnerabilities {
			fmt.Println(string(v.PluginId))
			vuln, err := Client.AssetVulnerabilityInfo(a.Id, string(v.PluginId))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(vuln.Info.Description)
			if vuln.Info.RiskInformation.CVSSTemporalScore != ""{
				score, err := vuln.Info.RiskInformation.CVSSTemporalScore.Float64()
				if err != nil {
					fmt.Println("error")
					log.Fatal(err)
				}
				fmt.Println("eaaar")
				auditedAsset.TotalRiskScore += score
			}
		}

		setAdjustedScore(&auditedAsset)
		score := fmt.Sprintf("%.6f", auditedAsset.TotalRiskScore)
		row := []string{a.IPv4List[0], score}
		resultTable.Rows = append(resultTable.Rows, row)
	}

	return &resultTable
}

func auditVulns(s *AuditState){

}

func setAdjustedScore(auditedAssets *util.AuditedAsset){
	for _, t := range auditedAssets.Tags{
		if t == "BIA-0"{
			auditedAssets.TotalRiskScore *= 2.5
		}

		if t == "BIA-1"{
			auditedAssets.TotalRiskScore *= 2
		}

		if t == "BIA-2"{
			auditedAssets.TotalRiskScore *= 1.5
		}
	}
}
