package vulners

type PocInfo interface {
	Scan(url string)
	Exploit(url string)
}
