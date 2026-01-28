package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var ShowToolsCmd = &cobra.Command{
	Use:   "show-tools",
	Short: "Shows all tools that are run by default in the fullrun command",
	Long:  `The 'show-tools' command lists all the tools that are executed by default when you run the 'fullrun' command. This is useful to understand the full scope of the automated assessment.`,
	Run: func(cmd *cobra.Command, args []string) {
		reconTools := []string{
			"subfinder",
			"amass",
			"bbot",
			"katana",
			"naabu",
			"wafw00f",
			"subzy",
		}

		scanTools := []string{
			"wafw00f",
			"paramspider",
			"httpx",
			"dalfox",
			"sqlmap",
			"enum4linux-ng",
			"nuclei",
			"nikto",
			"bbot",
			"ffuf",
			"dirsearch",
			"feroxbuster",
			"gobuster",
			"metasploit",
			"subzy",
			"attackmate",
			"sliver",
		}

		fmt.Println("--- Tools run by default in 'fullrun' ---")
		fmt.Println("\n[Recon Phase]")
		for _, tool := range reconTools {
			fmt.Printf("- %s\n", tool)
		}

		fmt.Println("\n[Scan Phase]")
		for _, tool := range scanTools {
			fmt.Printf("- %s\n", tool)
		}
	},
}

func init() {}


func init() {
	RootCmd.AddCommand(ShowToolsCmd)
}
