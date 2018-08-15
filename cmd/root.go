package cmd

import (
	"errors"
	"fmt"
	"github.com/DharmaOfCode/tenago/api"
	"github.com/DharmaOfCode/tenago/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"os"
	"runtime"
)

var (
	Verbose bool
	Threads int
	cfgFile string
	Client  *api.Client
	config  *util.Configuration
	rootCmd = &cobra.Command{
		Use:   "tenago",
		Short: "Tenago is a Tenable API go client with powerful commands.",
		Long: `A Tenable API go client with powerful commands
					created by Alex Useche
					Complete documentation is available at [TBD]`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("you must enter at least one arg")
			}
			return nil
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			err := viper.Unmarshal(&config)
			if Verbose {
				fmt.Printf("[+] Setting the application to %d threads\n", Threads)
			}
			runtime.GOMAXPROCS(Threads)
			if err != nil {
				log.Fatalf("unable to decode into struct, %v", err)
				os.Exit(1)
			}
			Client = api.NewClient(nil, config.Credentials.AccessKey, config.Credentials.SecretKey)
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is the base folder where tenago is located)")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().IntVarP(&Threads, "threads", "t", 10, "Number of threads (defaults to 10)")
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find in base
		viper.SetConfigName("config")
		viper.AddConfigPath(".")
	}

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
		os.Exit(1)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
