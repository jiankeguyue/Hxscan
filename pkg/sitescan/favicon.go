package sitescan

import (
	"bytes"
	"github.com/imroc/req/v3"
	"golang.org/x/net/html"
	"htmlquery"
	"strings"
)

func (r *siteRunner) getFavicon(resp *req.Response) (favicon string, iconHash string) {
	htmlDoc, err := html.Parse(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return favicon, iconHash
	}
	if nodes, err := htmlquery.QueryAll(htmlDoc, "//link"); err != nil {
		return favicon, iconHash
	} else {
		for _, node := range nodes {
			if htmlquery.SelectAttr(node, "href") != "" && strings.Contains(htmlquery.SelectAttr(node, "rel"), "icon") {
				favicon = htmlquery.SelectAttr(node, "href")
				break
			}
		}
	}

	if favicon == "" {
		return favicon, iconHash
	}

	if !strings.Contains(favicon, "http") {
		favicon = strings.TrimSpace(favicon)
		favicon = strings.TrimLeft(favicon, "../")
		favicon = strings.TrimLeft(favicon, "./")
		if !strings.HasPrefix(favicon, "/") {
			favicon = "/" + favicon
		}
		favicon = resp.Request.URL.Scheme + "://" + resp.Request.URL.Host + favicon
	}
	iconHash = r.GetHash(favicon)
	if iconHash == "" {
		favicon = ""
	}
	return favicon, iconHash

}

//func (r *siteRunner) main() {
//	url := "124.70.7.165:8043"
//	resp, err := req.Get(url)
//	if err != nil {
//		fmt.Errorf("Error occurred while getting ico: %v", err)
//	}
//	favicon, hash := r.getFavicon(resp)
//	fmt.Printf(favicon)
//	fmt.Println(hash)
//}
