package sitescan

import (
	"fmt"
	"github.com/logrusorgru/aurora"
)

type Result struct {
	Url           string
	StatusCode    int
	ContentLength int
	Favicon       string
	IconHash      string
	Title         string
	Wappalyzer    map[string]struct{}
	Fingers       []Fingerprint
}

type Results []*Result

func (s Results) Len() int {
	return len(s)
}
func (s Results) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s Results) Less(i, j int) bool {
	return s[i].ContentLength < s[j].ContentLength
}

func FmtResult(result *Result, noColor bool) (res string) {
	if noColor {
		res = fmt.Sprintf("%v [%v] [%v] [%v] [%v] [%v] [%v]\n", result.Url, result.StatusCode, result.ContentLength, result.IconHash, result.Title, GetWappalyzerString(result.Wappalyzer), GetFingerString(result.Fingers))
	} else {
		res = fmt.Sprintf("%v [%v] [%v] [%v] [%v] [%v] [%v]\n", result.Url, aurora.Red(result.StatusCode), aurora.Yellow(result.ContentLength), aurora.Blue(result.IconHash), aurora.Green(result.Title), aurora.Cyan(GetWappalyzerString(result.Wappalyzer)), aurora.Red(GetFingerString(result.Fingers)))
	}
	return
}

func GetWappalyzerString(result map[string]struct{}) (wappalyzerString string) {
	for k := range result {
		wappalyzerString += fmt.Sprintf("(%v)", k)
	}
	return
}

func GetFingerString(fingers []Fingerprint) (fingerString string) {
	for _, finger := range fingers {
		fingerString += fmt.Sprintf("(%v", finger.CMS)
		fingerString += ")"
	}
	return
}
