package webiport

import (
	"fmt"
	"regexp"
	"sitescan/internal/utils"
	"sitescan/pkg/sitescan"
	"strconv"
)

var rePort = regexp.MustCompile(`https?://.*?:(\d+)`)

func Run(host string, timeout, threads int, proxy string) (results []int) {
	ports, err := utils.ParsePortsList(utils.Webport)
	if err != nil {
		return
	}
	var urls []string
	for port := range ports {
		urls = append(urls, fmt.Sprintf("%v:%v", host, port))
	}

	urls = sitescan.JudgeAlive(urls, timeout, threads, proxy)

	for _, url := range urls {
		matches := rePort.FindAllStringSubmatch(url, -1)
		port, _ := strconv.Atoi(matches[0][1])
		results = append(results, port)
	}

	return results
}
