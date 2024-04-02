package sitescan

import (
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
	"strings"
	"sync"
	"time"
)

var (
	ToHttps = []string{
		"sent to HTTPS port",
		"This combination of host and port requires TLS",
		"Instead use the HTTPS scheme to",
		"This web server is running in SSL mode",
	}
)

func JudgeSingleAlive(client *req.Client, url string) (resp *req.Response, err error) {
	var scheme string
	var flag bool
	request := client.R()
	if !strings.HasPrefix(url, "http") {
		scheme = "http://"
		resp, err = request.Get(scheme + url)
		if err != nil {
			gologger.Debug().Msgf("request error for http, %v", err)
			scheme = "https://"
			flag = true
		} else {
			for _, str := range ToHttps {
				if strings.Contains(resp.String(), str) {
					scheme = "https://"
					flag = true
					break
				}
			}
		}
	} else if strings.HasPrefix(url, "http://") {
		resp, err = request.Get(url)
		if err != nil {
			gologger.Debug().Msgf("request error for http, %v", err)
			scheme = "https://"
			flag = true
			url = url[7:]
		} else {
			for _, str := range ToHttps {
				if strings.Contains(resp.String(), str) {
					scheme = "https://"
					flag = true
				}
			}
		}
	} else {
		flag = true
	}
	if flag {
		resp, err = request.Get(scheme + url)
	}
	return
}

func JudgeAlive(urls []string, timeout, threads int, proxy string) (results []string) {
	if len(urls) == 0 {
		fmt.Printf("[error] urls 为空，请输入有效的 url\n")
		return
	}
	gologger.Info().Msgf("开始 HTTP 存活验证： %v", len(urls))
	client := req.C()
	// 设置http客户端的超时时间
	client.SetTimeout(time.Duration(timeout) * time.Second)
	// 跳过证书验证，相当于python中的verify = False
	client.GetTLSClientConfig().InsecureSkipVerify = true
	if proxy != "" {
		client.SetProxyURL(proxy)
	}

	// 等待所有任务完成
	waitgroup := &sync.WaitGroup{}
	// 互斥锁，用于保护共享资源 results
	mutex := sync.Mutex{}
	// 存放还未被存货验证的 url,创造一个通道
	taskChan := make(chan string, threads)

	for i := 0; i < threads; i++ {
		go func() {
			for task := range taskChan {
				resp, err := client.R().Get("http://" + task)
				if err == nil {
					mutex.Lock()
					results = append(results, resp.Request.URL.String())
					mutex.Unlock()
				} else {
					gologger.Debug().Msgf("出现错误: %v", err)
					resp, err = client.R().Get("https://" + task)
					if err == nil {
						mutex.Lock()
						results = append(results, resp.Request.URL.String())
						mutex.Unlock()
					} else {
						gologger.Debug().Msgf("http与https均出现错误: %v", err)
					}
				}
				waitgroup.Done()
			}
		}()
	}

	for _, task := range urls {
		waitgroup.Add(1)
		taskChan <- task
	}
	close(taskChan)
	waitgroup.Wait()

	gologger.Info().Msgf("所有url HTTP 与 HTTPS探活结束")
	return
}
