package cmd

import (
	"github.com/spf13/cobra"
	"strings"
	"weaver-exploit/core"
	"weaver-exploit/vulners"
)

var exploitCmd = &cobra.Command{
	Use:   "exp",
	Short: "漏洞利用 WeaverScan.exe exp [flags] ",
	Long:  `漏洞利用模块`,
	Run: func(cmd *cobra.Command, args []string) {
		vulners.SetProxyURL(proxy)
		pocs := make(map[string]interface{})
		url = strings.Trim(url, "/")
		a := core.AddPoc(pocs)
		a[vulnId].(vulners.PocInfo).Exploit(url)
	},
}

func init() {
	rootCmd.AddCommand(exploitCmd)
	exploitCmd.Flags().StringVarP(&url, "targetUrl", "u", "", "targetUrl")
	exploitCmd.Flags().StringVarP(&proxy, "proxyUrl", "s", "", "设置HTTP代理 eg: http://127.0.0.1:8080")
	exploitCmd.Flags().StringVarP(&vulnId, "vulnId", "i", "", "vulnId")
	exploitCmd.MarkFlagRequired("targetUrl")
	exploitCmd.MarkFlagRequired("vulnId")
}
