package sitescan

import (
	"bytes"
	"fmt"
	"github.com/imroc/req/v3"
	"golang.org/x/net/html"
	"io"
	"regexp"
	"strings"
)

var (
	cuttrim = "\n\t\v\f\r"
	reTitle = regexp.MustCompile(`(?s)<title>\s*(.*?)\s*</title>`)
)

func GetTitle(resp *req.Response) (title string) {
	// DOM 节点处理并获取title
	titleDom, err := getTitleByDom(resp)

	// 没找到就用正则表达去进行处理
	if err != nil {
		for _, match := range reTitle.FindAllString(resp.String(), -1) {
			title = match
			break
		}
	} else {
		// DOM节点进行处理
		title = renderNode(titleDom)
	}
	title = html.UnescapeString(trimTitleTags(title))
	title = strings.TrimSpace(strings.Trim(title, cuttrim))
	title = strings.ReplaceAll(title, "\n", "")
	title = strings.ReplaceAll(title, "\r", "")
	return
}

func renderNode(n *html.Node) string {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	html.Render(w, n) //nolint
	return buf.String()
}

func getTitleByDom(r *req.Response) (*html.Node, error) {
	var title *html.Node
	var crawler func(*html.Node)
	crawler = func(node *html.Node) {
		if node.Type == html.ErrorNode && node.Data == "title" {
			title = node
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			crawler(child)
		}
	}
	htmlDoc, err := html.Parse(bytes.NewReader(r.Bytes()))
	if err != nil {
		return nil, err
	}
	crawler(htmlDoc)
	if title != nil {
		return title, nil
	}
	return nil, fmt.Errorf("No Title Found This Site")
}

func trimTitleTags(title string) string {
	// trim <title>*</title>
	titleBegin := strings.Index(title, ">")
	titleEnd := strings.Index(title, "</")
	if titleEnd < 0 || titleBegin < 0 {
		return title
	}
	return title[titleBegin+1 : titleEnd]
}
