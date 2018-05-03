package util

import (
	"github.com/olekukonko/tablewriter"
	"os"
	"fmt"
)


func PrintResult(verbose bool, result *ResultTable){
	fmt.Println()
	PrintRuler(verbose)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(result.Columns)
	table.SetBorder(false)

	var headerColors []tablewriter.Colors
	for i, _ := range result.Columns{
		if i == 0{
			headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.BgGreenColor})
		} else {
			headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.BgGreenColor})
		}
	}
	table.SetHeaderColor(headerColors...)

	var rowColors []tablewriter.Colors
	for i, _ := range result.Columns{
		if i == 0{
			rowColors = append(rowColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor})
		} else {
			rowColors = append(rowColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor})
		}
	}
	table.SetColumnColor(rowColors...)


	table.SetColumnColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor})


	table.AppendBulk(result.Rows)
	table.Render()
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