package sitescan

import (
	"encoding/json"
	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
	"io/ioutil"
	"sitescan/internal/utils"
	"strings"
)

type Fingerprint struct {
	CMS      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

type FingerRules []*Fingerprint

func (f FingerRules) Len() int {
	return len(f)
}
func (f FingerRules) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}
func (f FingerRules) Less(i, j int) bool {
	return f[i].CMS < f[j].CMS
}

func ReadfromJson() map[string][]Fingerprint {
	filePath := "finger.json"
	jsonData, err := ioutil.ReadFile(filePath)
	if err != nil {
		gologger.Debug().Msgf("读取文件出现问题：%v", err)
	}

	var data map[string][]Fingerprint
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		gologger.Debug().Msgf("解析json文件出现问题：%v", err)
	}

	return data
}

func (r *siteRunner) getFinger(resp *req.Response, rules map[string][]Fingerprint) (results []Fingerprint) {
	bodyString := resp.String()
	headerString := utils.GetHeaderString(resp)
	_, icohash := r.getFavicon(resp)
	//certString := utils.GetCert(resp)
	//iconMap := map[string]string{}
	var toMatch string
	//var rules string
	//var flag2 bool
	//var flag3 int
	// 多个 FingerRules
	for _, fingerRule := range rules["fingerprint"] {
		if fingerRule.Method == "keyword" {
			if fingerRule.Location == "body" {
				toMatch = bodyString
			}
			if fingerRule.Location == "header" {
				toMatch = headerString
			}
		} else if fingerRule.Method == "faviconhash" {
			toMatch = icohash
		}
		for _, k := range fingerRule.Keyword {
			var num int
			num = 0
			if strings.Contains(toMatch, k) {
				num++
			}
			if num == len(fingerRule.Keyword) {
				result := fingerRule
				results = append(results, result)
			} else {
				continue
			}
		}
		// 单个 fingerRule 多个 finger
		//for _, finger := range fingerRule.Fingers {
		//	flag3 = 0
		//	// 单个 finger 多个 rules
		//	for _, rule := range finger.Rules {
		//		flag2 = false
		//		if rule.Method == "keyword" {
		//			if rule.Location == "body" {
		//				toMatch = bodyString
		//			}
		//			if rule.Location == "header" {
		//				toMatch = headerString
		//			}
		//		} else if rule.Method == "iconhash" {
		//			if value, ok := iconMap[rule.Location]; ok {
		//				toMatch = value
		//			} else {
		//				toMatch = r.GetHash(resp.Request.URL.Scheme + "://" + resp.Request.URL.Host + rule.Location)
		//				iconMap[rule.Location] = toMatch
		//			}
		//		}
		//		if strings.Contains(toMatch, rule.Keyword) {
		//			flag2 = true
		//		}
		//		if flag2 {
		//			// 当前成立,为and继续循环,为or直接成立
		//			if finger.Type == "and" {
		//				flag3 += 1
		//				rules += fmt.Sprintf("%v %v %v | ", rule.Method, rule.Location, rule.Keyword)
		//			} else if finger.Type == "or" {
		//				flag1 = true
		//				rules = fmt.Sprintf("%v %v %v", rule.Method, rule.Location, rule.Keyword)
		//				break
		//			}
		//		} else {
		//			// 当前不成立,为and直接不成立
		//			if finger.Type == "and" {
		//				break
		//			}
		//		}
		//	}
		//	if flag3 == len(finger.Rules) {
		//		flag1 = true
		//	}
	}
	return
}
