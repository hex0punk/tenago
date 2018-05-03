package cmd

import (
	"github.com/spf13/cobra"
	"fmt"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Tenago",
	Long:  `All software has versions. This is Tenago's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Tenago Tenable API Client v0.1 -- HEAD")
	},
}
