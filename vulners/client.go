package vulners

import (
	"github.com/imroc/req/v3"
	"time"
)

var baseClient *req.Client
var proxyURL = ""

func SetProxyURL(URL string) {
	proxyURL = URL
	init1()

}

func init1() {
	if proxyURL != "" {
		baseClient = req.C().SetProxyURL(proxyURL).
			EnableInsecureSkipVerify().
			SetTimeout(10 * time.Second).
			SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36")
	} else {
		baseClient = req.C().
			EnableInsecureSkipVerify().
			SetTimeout(10 * time.Second).
			SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36")
	}

}
