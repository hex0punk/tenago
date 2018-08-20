package util

import (
	"github.com/olekukonko/tablewriter"
	"os"
	"fmt"
	"github.com/fatih/color"
)


func PrintResult(verbose bool, result *ResultTable){
	fmt.Println()
	PrintRuler(verbose)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(result.Columns)
	table.SetBorder(false)

	var headerColors []tablewriter.Colors
	for i := range result.Columns{
		if i == 0{
			headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.BgGreenColor})
		} else {
			headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.BgGreenColor})
		}
	}
	table.SetHeaderColor(headerColors...)

	var rowColors []tablewriter.Colors
	for i := range result.Columns{
		if i == 0{
			rowColors = append(rowColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor})
		} else {
			rowColors = append(rowColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor})
		}
	}
	table.SetColumnColor(rowColors...)

	//TODO: update footer so it can contain keys and values
	//table.SetFooter([]string{"", "", "Total", "$146.93"}) // Add Footer
	//table.SetFooterColor(tablewriter.Colors{}, tablewriter.Colors{},
	//	tablewriter.Colors{tablewriter.Bold},
	//	tablewriter.Colors{tablewriter.FgHiRedColor})

	table.AppendBulk(result.Rows)
	table.Render()

	if result.Footer != ""{
		c := color.New(color.FgMagenta).Add(color.Underline)
		PrintRuler(true)
		c.Println(result.Footer)
		PrintRuler(true)
	}

	if verbose{
		fmt.Printf("[+] Total records: %d\n", len(result.Rows))
		PrintRuler(true)
	}
}

func PrintBanner(verbose bool) {
	if verbose {
		fmt.Println("")
		fmt.Println("go-tenable			By Alex Useche")
		PrintRuler(verbose)
	}
}

func PrintRuler(verbose bool) {
	if verbose {
		fmt.Println("==============================================================")
	}
}