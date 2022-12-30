package core

import (
	"github.com/imroc/req/v3"
	"strings"
	"time"
)

var checkClient *req.Client

func init() {
	checkClient = req.C().
		EnableInsecureSkipVerify().
		SetTimeout(10 * time.Second).
		SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36")
}

func Checkmod(url string) int {
	var checkurl = []string{
		"/cloudstore/resource/index.js",
		"/wui/theme/ecologyBasic/page/images/toolbarBg.png",
		"/wui/theme/ecologyBasic/page/images/toolbarBg_wev8.png",
		"/general/login/view/css/login.css",
		"/page/manage/images/logo.png"}

	cology, _ := checkClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(url + checkurl[0])
	cology1, _ := checkClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(url + checkurl[1])
	cology2, _ := checkClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(url + checkurl[2])
	office, _ := checkClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(url + checkurl[3])
	mobile, _ := checkClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(url + checkurl[4])
	base, _ := checkClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(url)
	baseresp := base.String()
	cologyresp := cology.String()
	cology1resp := cology1.String()
	cology2resp := cology2.String()
	officeresp := office.String()
	mobile1resp := mobile.String()
	if strings.Contains(baseresp, "mobile") {
		return 2
	} else if strings.Contains(cologyresp, "function") || strings.Contains(cology1resp, "PNG") || strings.Contains(cology2resp, "PNG") {
		return 1
	} else if strings.Contains(officeresp, "cursor") {
		return 3
	} else if strings.Contains(mobile1resp, "PNG") {
		return 2
	} else {
		return 0
	}

}
