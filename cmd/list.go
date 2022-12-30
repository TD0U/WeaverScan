package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	CologyVulnNames = []string{
		"  泛微E-Cology_SignatureDownLoad_任意文件读取",           //1
		"  泛微E-Cology_Weaver.common.Css_任意文件上传[比较复杂暂未完成]", //2
		"  泛微E-Cology_Getdata_SQL注入",                      //3
		"  泛微E-Cology_LoginSSO_SQL注入",                     //4
		"  泛微E-Cology_KtreeUploadAction_任意文件上传",           //5
		"  泛微E-Cology_HrmCareerApplyPerView_SQL注入",        //6
		"  泛微E-Cology_bah_远程代码执行漏洞",                       //7
		"  泛微E-Cology_VerifyQuickLogin_任意用户登录",            //8
		"  泛微E-Cology_UploadFileClient_任意文件上传",            //9
		" 泛微E-Cology_jqueryFileTree_目录遍历",                 //10
		" 泛微E-Cology_users.data_敏感信息泄漏",                   //11
		" 泛微E-Cology_FileDownload_任意文件读取",                 //12
		" 泛微E-Cology_UploaderOperate_任意文件上传",              //13
		" 泛微E-Cology_weaver.common.Ctrl_权限绕过",             //14
		" 泛微E-Cology_WorkflowServiceXml_命令执行"}

	OfficeVulnNames = []string{
		"  泛微E-office_group_xml_SQL注入",      //1
		"  泛微E-office_do_excel_任意文件写入",      //2
		"  泛微E-office_UserSelect_未授权访问",     //3
		"  泛微E-office_UploadFile_任意文件上传",    //4
		"  泛微E-office_OfficeServer_任意文件上传",  //5
		"  泛微E-office_Officeserver_任意文件读取",  //6
		"  泛微E-office_UploadFile[1]_任意文件上传", //7
		"  泛微E-office_mysql_config_数据库信息泄露"}

	MobileVulnNames = []string{
		"  泛微E-Mobile_Client.do_命令执行[数据包过于复杂还没写]", //1
		"  泛微E-Mobile_Login.do_表达式注入"}
)
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "列出所有漏洞信息",
	Long:  `完整的漏洞列表及对应ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		for i, v := range MobileVulnNames {
			fmt.Printf("【%v】%v\n", i+1, v)
		}
		for i, v := range OfficeVulnNames {
			fmt.Printf("【%v】%v\n", i+1, v)
		}
		for i, v := range CologyVulnNames {
			fmt.Printf("【%v】%v\n", i+1, v)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
