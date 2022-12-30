package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

var (
	mod    int
	url    string
	vulnId string
	proxy  string
)
var rootCmd = &cobra.Command{
	Use:   "WeaverScan",
	Short: "WeaverScan",
	Long: "                                                                                     \n" +
		"██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗\n" +
		"██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║\n" +
		"██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║\n" +
		"██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║\n" +
		"╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║███████║╚██████╗██║  ██║██║ ╚████║\n" +
		" ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n\n" +
		"                                                           @author:TDOU\n" +
		"                                                           @version:1.0",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().StringVarP(&url, "targetUrl", "u", "", "targetUrl")
	rootCmd.Flags().StringVarP(&proxy, "proxyUrl", "s", "", "设置HTTP代理 eg: http://127.0.0.1:8080")
	rootCmd.Flags().StringVarP(&vulnId, "vulnId", "i", "", "默认为空检测所有漏洞")
}
