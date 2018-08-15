package cmd

import (
	"errors"
	"fmt"
	"github.com/DharmaOfCode/tenago/api"
	"github.com/DharmaOfCode/tenago/util"
	"github.com/spf13/cobra"
	"log"
	"strings"
	"time"
)

type QueryState struct {
	Assets          bool
	Targets         bool
	Scans           bool
	Vulnerabilities bool

	IP          string
	Hostname    string
	TargetGroup string
	ScanName    string

	VulnQuery api.VulnQuery
}

var (
	queryState QueryState

	queryCmd = &cobra.Command{
		Use:   "query",
		Short: "Queries assets, scans, target groups and vulnerabilities.",
		Long:  `Queries assets, scans, target groups and vulnerabilities.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if !queryState.Targets && !queryState.Assets && !queryState.Scans && !queryState.Vulnerabilities {
				return errors.New("you need to tell me what to query (target groups or assets)")
			}
			if queryState.Vulnerabilities {
				if queryState.VulnQuery.Severity != ""{
					queryState.VulnQuery.Severity = strings.ToLower(queryState.VulnQuery.Severity)
					validValues := []string{"info", "low", "medium", "high", "critical"}
					if !stringInSlice(queryState.VulnQuery.Severity, validValues) {
						return errors.New("invalid severity")
					}
				}
				if queryState.VulnQuery.State != ""{
					queryState.VulnQuery.State= strings.ToLower(queryState.VulnQuery.State)
					queryState.VulnQuery.State= strings.Title(queryState.VulnQuery.State)
					validValues := []string{"New", "Fixed", "Active", "Resurfaced"}
					if !stringInSlice(queryState.VulnQuery.Severity, validValues) {
						return errors.New("invalid severity")
					}
				}
			}
			return nil
		},
		Run: runQuery,
	}
)

func init() {
	queryState = QueryState{}
	queryCmd.Flags().StringVar(&queryState.IP, "ip", "", "the IP address to use in the search")
	queryCmd.Flags().StringVar(&queryState.Hostname, "hostname", "", "The hostname to use in a search")
	queryCmd.Flags().StringVar(&queryState.TargetGroup, "target", "", "The target group to search by")
	queryCmd.Flags().StringVar(&queryState.ScanName, "scan", "", "The scan name to search by")

	queryCmd.Flags().StringVar(&queryState.VulnQuery.Severity, "severity", "", "The severity to query by")
	queryCmd.Flags().StringVar(&queryState.VulnQuery.State, "state", "", "The vulnerability state")
	queryCmd.Flags().IntVar(&queryState.VulnQuery.DateRange, "days", 30, "The amount of days for data collection")

	queryCmd.Flags().BoolVarP(&queryState.Assets, "query assets", "A", false, "Search assets")
	queryCmd.Flags().BoolVarP(&queryState.Targets, "query target groups", "T", false, "Search target groups")
	queryCmd.Flags().BoolVarP(&queryState.Scans, "query scans", "S", false, "Search scans by name or hostname")
	queryCmd.Flags().BoolVarP(&queryState.Vulnerabilities, "query vulnerabilities", "V", false, "Search vulnerabilities, all or by severity")

	rootCmd.AddCommand(queryCmd)
}

func runQuery(cmd *cobra.Command, args []string) {
	valid := true

	if queryState.Assets && queryState.TargetGroup != "" {
		fmt.Println("[!] You cannot query assets by target groups")
		valid = false
	}

	if !valid {
		util.PrintRuler(Verbose)
		errors.New("error running query command")
	} else {
		processQuery(&queryState)
	}
}

func processQuery(s *QueryState) {
	var result *util.ResultTable
	if Verbose{
		fmt.Println("Preparing query...")
	}

	if s.Targets {
		result = queryTargets(s)
	}

	if s.Assets {
		result = queryAssets(s)
	}

	if s.Scans {
		result = queryScans(s)
	}

	if s.Vulnerabilities {
		result = queryVulnerabilities(s)
	}

	if s.Assets && (s.IP == "" && s.Hostname == "" && s.TargetGroup == "") {
		result = getAllAssets(s)
	}

	if s.Targets && (s.IP == "" && s.Hostname == "" && s.TargetGroup == "") {
		result = getAllTargets(s)
	}
	util.PrintResult(Verbose, result)
}

func queryVulnerabilities(s *QueryState) *util.ResultTable {
	start := time.Now()
	var vulns *api.VulnerabilitiesList
	var err error
	if s.VulnQuery.Severity != "" {
		if err != nil {
			log.Fatal(err)
		}
		vulns, err = Client.ListVulnerabilitiesBySeverity(s.VulnQuery)
	} else {
		vulns, err = Client.ListVulnerabilities(s.VulnQuery.DateRange)
	}

	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"ID", "Plugin Name", "Severiy", "Count", "State"}
	resultTable := util.ResultTable{
		Columns: columns,
	}

	if vulns == nil {
		return &resultTable
	}
	var count int64 = 0
	for _, v := range vulns.Vulnerabilities {
		row := []string{string(v.PluginId), v.PluginName, v.Severity.String(), string(v.Count), v.VulnerabilityState}
		resultTable.Rows = append(resultTable.Rows, row)
		c, err := v.Count.Int64()
		if err != nil {
			log.Fatal(err)
		}
		count += c
	}

	if Verbose {
		util.PrintRuler(Verbose)
		fmt.Printf("%.2fs elapsed\n", time.Since(start).Seconds())

		util.PrintRuler(Verbose)
		fmt.Printf("Found a total of %d vulnerabilities\n", count)
		util.PrintRuler(Verbose)
	}

	return &resultTable
}

func queryScans(s *QueryState) *util.ResultTable {
	start := time.Now()
	scansList, err := Client.ListScans()
	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"Scan Name", "Targets"}
	resultTable := util.ResultTable{
		Columns: columns,
	}

	ch := make(chan *api.ScanDetails)
	for _, scan := range scansList.Scans {
		if s.ScanName != "" {
			lName := strings.ToLower(scan.Name)
			lTerm := strings.ToLower(s.ScanName)

			if strings.Contains(lName, lTerm) {
				if Verbose {
					fmt.Println("[+] Getting details for scan " + scan.Name)
				}
				info, err := Client.ScanDetails(string(scan.Id))
				if err != nil {
					log.Fatal(err)
				}
				row := []string{scan.Name, info.ScanInfo.Targets}
				resultTable.Rows = append(resultTable.Rows, row)
			}
		} else {
			if Verbose {
				fmt.Println("[+] Getting details for scan " + scan.Name)
			}
			go Client.ScanDetailsWithChannel(string(scan.Id), ch)
		}
	}

	for range scansList.Scans {
		info := <-ch
		if Verbose {
			fmt.Println("[+] Received data for scan " + info.ScanInfo.Name)
		}
		targetsArray := strings.Split(info.ScanInfo.Targets, ",")
		if s.IP != "" {
			if contains(targetsArray, s.IP) {
				row := []string{info.ScanInfo.Name, info.ScanInfo.Targets}
				resultTable.Rows = append(resultTable.Rows, row)
			}
		}
		if s.Hostname != "" {
			if contains(targetsArray, s.Hostname) {
				row := []string{info.ScanInfo.Name, info.ScanInfo.Targets}
				resultTable.Rows = append(resultTable.Rows, row)
			}
		}
	}

	if Verbose {
		util.PrintRuler(Verbose)
		fmt.Printf("%.2fs elapsed\n", time.Since(start).Seconds())
	}

	return &resultTable
}

func queryTargets(s *QueryState) *util.ResultTable {
	targetGroupsList, err := Client.ListTargetGroups()
	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"Group Name", "Members"}
	resultTable := util.ResultTable{
		Columns: columns,
	}

	for _, t := range targetGroupsList.TargetGroups {
		membersArray := strings.Split(t.Members, ",")
		if s.TargetGroup != "" {
			lName := strings.ToLower(t.Name)
			lTerm := strings.ToLower(s.TargetGroup)

			if strings.Contains(lName, lTerm) {
				row := []string{t.Name, t.Members}
				resultTable.Rows = append(resultTable.Rows, row)
			}
		}
		if s.IP != "" {
			if contains(membersArray, s.IP) {
				row := []string{t.Name, t.Members}
				resultTable.Rows = append(resultTable.Rows, row)
			}
		}
		if s.Hostname != "" {
			if contains(membersArray, s.Hostname) {
				row := []string{t.Name, t.Members}
				resultTable.Rows = append(resultTable.Rows, row)
			}
		}
	}

	return &resultTable
}

func queryAssets(s *QueryState) *util.ResultTable {
	assetsList, err := Client.ListAssets()

	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"Asset ID", "Members", "Hostnames"}
	resultTable := util.ResultTable{
		Columns: columns,
	}

	for _, a := range assetsList.Assets {
		hostnames := "none"
		if a.HostnameList != nil {
			hostnames = strings.Join(a.HostnameList, "")
		}
		if s.IP != "" {
			if contains(a.IPv4List, s.IP) {
				ips := strings.Join(a.IPv4List, ",")
				row := []string{a.Id, ips, hostnames}
				resultTable.Rows = append(resultTable.Rows, row)
			}
		}
		if s.Hostname != "" {
			if contains(a.NetbiosName, s.Hostname) {
				names := strings.Join(a.NetbiosName, ",")
				row := []string{a.Id, names, hostnames}
				resultTable.Rows = append(resultTable.Rows, row)
			}
		}
	}

	return &resultTable
}

func getAllAssets(s *QueryState) *util.ResultTable {
	assetsList, err := Client.ListAssets()

	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"Hostname", "IP Address"}
	resultTable := util.ResultTable{
		Columns: columns,
	}

	for _, a := range assetsList.Assets {
		var name string
		if len(a.NetbiosName) > 0 {
			name = a.NetbiosName[0]
		} else {
			name = a.IPv4List[0]
		}
		row := []string{name, a.IPv4List[0]}
		resultTable.Rows = append(resultTable.Rows, row)
	}

	return &resultTable
}

func getAllTargets(s *QueryState) *util.ResultTable {
	targetGroupsList, err := Client.ListTargetGroups()

	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"Group Name", "Members"}
	resultTable := util.ResultTable{
		Columns: columns,
	}

	for _, t := range targetGroupsList.TargetGroups {
		row := []string{t.Name, t.Members}
		resultTable.Rows = append(resultTable.Rows, row)
	}

	return &resultTable
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if strings.Contains(strings.ToLower(a), strings.ToLower(e)) {
			return true
		}
	}
	return false
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
