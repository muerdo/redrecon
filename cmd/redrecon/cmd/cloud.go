package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"redrecon/pkg/cloud"
	"redrecon/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	cloudTarget    string
	cloudProxies   utils.StringSliceFlag
	cloudProxyFile string
)

var CloudCmd = &cobra.Command{
	Use:   "cloud <domain>",
	Short: "Performs cloud reconnaissance/enumeration (Azure, AWS, GCP).",
	Long: `The 'cloud' command focuses on enumerating cloud resources associated with a target domain.
It is particularly effective against Azure AD (Entra ID) and AWS S3 buckets.

☁ **Features:**
- **Azure Tenant Enum:** Checks for Azure AD presence and extracts Tenant ID / OpenID config.
- **Nuclei Cloud:** Runs specialized Nuclei templates for cloud asset discovery.
- **Cloud Enum:** Integration with standard bucket enumeration flows.

💪 **Best Practices:**
- Use this against the root domain (e.g., example.com).
- Combine with OSINT to find hidden assets.
- If Azure is detected, consider using specific Azure tools like 'roadrecon' or 'o365spray' (not included) for deeper user spraying.

Example:
  redrecon cloud example.com
  redrecon cloud example.com --proxy-file proxies.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			cloudTarget = args[0]
		}

		if cloudTarget == "" {
			slog.Error("Target domain must be specified")
			return
		}

		logFile, err := os.OpenFile("redrecon.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer logFile.Close()
		logger := slog.New(slog.NewTextHandler(logFile, nil))
		fmt.Println("Logs being written to redrecon.log")

		ctx := context.Background()

		// Proxy Setup
		var proxyManager *utils.ProxyManager
		var proxies []string
		if len(cloudProxies) > 0 {
			proxies = cloudProxies
		} else if cloudProxyFile != "" {
			loaded, err := utils.ReadLines(cloudProxyFile)
			if err == nil {
				proxies = loaded
			}
		}
		proxyManager = utils.NewProxyManagerFromList(proxies)

		if err := cloud.StartCloudRecon(ctx, cloudTarget, proxyManager, logger); err != nil {
			logger.Error("Cloud Recon failed", "error", err)
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println("Cloud Recon Finished successfully. Check results folder.")
		}
	},
}

func init() {
	CloudCmd.Flags().StringVarP(&cloudTarget, "target", "t", "", "Target domain (e.g., example.com)")
	CloudCmd.Flags().Var(&cloudProxies, "proxies", "List of proxies to use")
	CloudCmd.Flags().StringVar(&cloudProxyFile, "proxy-file", "", "File containing proxies")
}


func init() {
	RootCmd.AddCommand(CloudCmd)
}
