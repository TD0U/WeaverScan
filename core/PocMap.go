package core

import (
	"weaver-exploit/vulners"
)

func AddPoc(pocs map[string]interface{}) map[string]interface{} {
	pocs["Wc01"] = &vulners.Wc01{}
	pocs["Wc02"] = &vulners.Wc02{}
	pocs["Wc03"] = &vulners.Wc03{}
	pocs["Wc04"] = &vulners.Wc04{}
	pocs["Wc05"] = &vulners.Wc05{}
	pocs["Wc06"] = &vulners.Wc06{}
	pocs["Wc07"] = &vulners.Wc07{}
	pocs["Wc08"] = &vulners.Wc08{}
	pocs["Wc09"] = &vulners.Wc09{}
	pocs["Wc10"] = &vulners.Wc10{}
	pocs["Wc11"] = &vulners.Wc11{}
	pocs["Wc12"] = &vulners.Wc12{}
	pocs["Wc13"] = &vulners.Wc13{}
	pocs["Wc14"] = &vulners.Wc14{}
	pocs["Wc15"] = &vulners.Wc15{}
	pocs["Wm01"] = &vulners.Wm01{}
	pocs["Wm02"] = &vulners.Wm02{}
	pocs["Wo01"] = &vulners.Wo01{}
	pocs["Wo02"] = &vulners.Wo02{}
	pocs["Wo03"] = &vulners.Wo03{}
	pocs["Wo04"] = &vulners.Wo04{}
	pocs["Wo05"] = &vulners.Wo05{}
	pocs["Wo06"] = &vulners.Wo06{}
	pocs["Wo07"] = &vulners.Wo07{}
	pocs["Wo08"] = &vulners.Wo08{}
	return pocs
}

func AddWcPoc(pocs map[string]interface{}) map[string]interface{} {
	pocs["Wc01"] = &vulners.Wc01{}
	pocs["Wc02"] = &vulners.Wc02{}
	pocs["Wc03"] = &vulners.Wc03{}
	pocs["Wc04"] = &vulners.Wc04{}
	pocs["Wc05"] = &vulners.Wc05{}
	pocs["Wc06"] = &vulners.Wc06{}
	pocs["Wc07"] = &vulners.Wc07{}
	pocs["Wc08"] = &vulners.Wc08{}
	pocs["Wc09"] = &vulners.Wc09{}
	pocs["Wc10"] = &vulners.Wc10{}
	pocs["Wc11"] = &vulners.Wc11{}
	pocs["Wc12"] = &vulners.Wc12{}
	pocs["Wc13"] = &vulners.Wc13{}
	pocs["Wc14"] = &vulners.Wc14{}
	pocs["Wc15"] = &vulners.Wc15{}
	return pocs
}
func AddWmPoc(pocs map[string]interface{}) map[string]interface{} {
	pocs["Wm01"] = &vulners.Wm01{}
	pocs["Wm02"] = &vulners.Wm02{}
	return pocs
}
func AddWoPoc(pocs map[string]interface{}) map[string]interface{} {
	pocs["Wo01"] = &vulners.Wo01{}
	pocs["Wo02"] = &vulners.Wo02{}
	pocs["Wo03"] = &vulners.Wo03{}
	pocs["Wo04"] = &vulners.Wo04{}
	pocs["Wo05"] = &vulners.Wo05{}
	pocs["Wo06"] = &vulners.Wo06{}
	pocs["Wo07"] = &vulners.Wo07{}
	pocs["Wo08"] = &vulners.Wo08{}
	return pocs
}
