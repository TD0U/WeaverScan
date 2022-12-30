package core

type Weavers interface {
	Scan(url string)
	Exploit(url string)
}
