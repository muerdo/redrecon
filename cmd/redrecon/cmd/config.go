package cmd

import (
	"fmt"
	"sort"

	"redrecon/internal/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage redrecon configuration",
	Long: `Access and modify redrecon configuration values directly from the CLI.
You can get, set, and list configuration keys. Changes are saved to your config file.

Examples:
  # Set the path to your XSS wordlist
  redrecon config set wordlists.xss /path/to/xss_payloads.txt

  # Set the path to your SQLi wordlist
  redrecon config set wordlists.sqli /path/to/sqli_payloads.txt

  # Get the current value of a key
  redrecon config get wordlists.xss

  # List all configuration keys and values
  redrecon config list
`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long:  `Sets a configuration value and saves it to the config file.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		value := args[1]

		viper.Set(key, value) // Set value in memory

		// Attempt to save to disk
		if err := config.SaveConfig(); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			return
		}

		fmt.Printf("Successfully set '%s' to '%s'\n", key, value)
		fmt.Printf("Configuration saved to: %s\n", viper.ConfigFileUsed())
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Long:  `Retrieves the current value of a configuration key.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		val := viper.Get(key)

		if val == nil {
			fmt.Printf("Key '%s' not found or not set.\n", key)
			return
		}

		fmt.Printf("%s: %v\n", key, val)
	},
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration values",
	Long:  `Lists all current configuration keys and their values.`,
	Run: func(cmd *cobra.Command, args []string) {
		keys := viper.AllKeys()
		sort.Strings(keys)

		fmt.Println("Current Configuration:")
		fmt.Println("----------------------")
		for _, key := range keys {
			val := viper.Get(key)
			fmt.Printf("%s: %v\n", key, val)
		}
	},
}

func init() {
	ConfigCmd.AddCommand(configSetCmd)
	ConfigCmd.AddCommand(configGetCmd)
	ConfigCmd.AddCommand(configListCmd)
	RootCmd.AddCommand(ConfigCmd)
}
