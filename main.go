package main

import (
	"fmt"
	"github.com/imroc/req/v3"
	"sitescan/cmd"
	"sitescan/internal/utils"
	"sitescan/pkg/sitescan"
)

func testTitle() {
	url := "http://59.45.21.50:8055/"
	resp, err := req.Get(url)
	if err != nil {
		fmt.Errorf("Error occurred while getting title: %v", err)
	}
	title := sitescan.GetTitle(resp)

	if err != nil {
		fmt.Errorf("Error occurred while getting title: %v", err)
	}
	fmt.Println("获取到的title为:", title)
}

func testLive() {
	urls := []string{"124.70.7.165:8043", "159.138.7.62"} // 替换为你要测试的URL列表
	timeout := 2                                          // 替换为你的超时时间
	threads := 2                                          // 替换为你的线程数
	proxy := ""                                           // 替换为你的代理设置，如果没有则留空

	results := sitescan.JudgeAlive(urls, timeout, threads, proxy)

	// 检查结果是否符合预期
	expectedLength := len(urls) // 预期结果长度与URL列表长度相同
	if len(results) != expectedLength {
		fmt.Errorf("结果长度不符合预期，预期长度：%d，实际长度：%d", expectedLength, len(results))
	}
	fmt.Println(results)

}

func testurljump() {
	url := "http://121.15.211.134:8088"
	resp, err := req.Get(url)
	if err != nil {
		fmt.Errorf("Error occurred while getting ico: %v", err)
	}
	result := sitescan.Urljump(resp)
	fmt.Println(result)

}

func main() {
	utils.Title()
	cmd.Execute()
}
