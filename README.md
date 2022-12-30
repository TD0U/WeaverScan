# WeaverScan

泛微漏洞利用工具 用go造了个轮子

![image](https://user-images.githubusercontent.com/75050574/210070916-fc0418ce-9de9-463b-9772-6e529df77b29.png)

## 漏洞检测

不指定漏洞Id 自动检测所有漏洞

```
WeaverScan.exe scan -u http://127.0.0.1
```

![image](https://user-images.githubusercontent.com/75050574/210070926-8551029d-4cc0-4d04-adc2-1f18a2df1efb.png)

指定Id

```
WeaverScan.exe scan -u http://127.0.0.1 -i Wc11
```
![image](https://user-images.githubusercontent.com/75050574/210070936-5e322325-43b4-4086-ba1b-face808e640e.png)

## 漏洞利用

```
WeaverScan.exe exp -u http://127.0.0.1 -i Wc05
```

![image](https://user-images.githubusercontent.com/75050574/210070942-c70ee22d-4817-459e-9799-aaf0ddd7c1e1.png)

## 代理

```
WeaverScan.exe exp -u http://127.0.0.1 -i Wc05  -s http://127.0.0.1:8080
WeaverScan.exe scan -u http://127.0.0.1 -i Wc11  -s http://127.0.0.1:8080
```

