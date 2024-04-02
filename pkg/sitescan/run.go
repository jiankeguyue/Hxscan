package sitescan

import (
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"net/http"
	"sitescan/internal/utils"
	"sync"
)

type Options struct {
	Proxy        string
	Threads      int
	Timeout      int
	Headers      []string
	NoColor      bool
	NoShiro      bool
	NoIconhash   bool
	NoWappalyzer bool
	FingerRules  []*Fingerprint
}

type siteRunner struct {
	options          *Options
	reqClient        *req.Client
	wappalyzerClient *wappalyzer.Wappalyze
}

func NewRunner(options *Options) (runner *siteRunner, err error) {
	runner = &siteRunner{
		options:   options,
		reqClient: utils.NewReqClient(options.Proxy, options.Timeout, options.Headers),
	}
	if !options.NoShiro {
		rememberMeCookie := utils.RandLetters(3)
		shiroCookie := &http.Cookie{
			Name:     "rememberMe",
			Value:    rememberMeCookie,
			Path:     "/",
			Domain:   "/",
			MaxAge:   36000,
			HttpOnly: false,
			Secure:   true,
		}
		runner.reqClient.SetCommonCookies(shiroCookie) // check shiro
	}
	if !options.NoWappalyzer {
		runner.wappalyzerClient, err = wappalyzer.New()
		if err != nil {
			return nil, err
		}
	}
	return runner, nil
}

func (r *siteRunner) Run(urls []string) (results Results) {
	if len(urls) == 0 {
		return
	}
	gologger.Info().Msgf("开始批量 urls web扫描")
	waitgroup := &sync.WaitGroup{}
	mutex := sync.Mutex{}
	taskChan := make(chan string, r.options.Threads)
	for i := 0; i < r.options.Threads; i++ {
		go func() {
			for task := range taskChan {
				resp, err := r.webinfo(task)
				if err != nil {
					gologger.Debug().Msgf("探测url存活时出现问题: %v", err)
				} else {
					//判断蜜罐
					if len(resp.Fingers) > 5 {
						gologger.Silent().Msgf(FmtResult(resp, r.options.NoColor))
						gologger.Warning().Msgf("%v 可能探测到蜜罐", resp.Url)
					} else {
						gologger.Silent().Msgf(FmtResult(resp, r.options.NoColor))
						mutex.Lock()
						results = append(results, resp)
						mutex.Unlock()
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

	gologger.Info().Msgf("扫描结束")

	return

}

func (r *siteRunner) webinfo(url string) (result *Result, err error) {
	resp, err := JudgeSingleAlive(r.reqClient, url)
	if resp == nil {
		fmt.Println("resp 为： ", resp)
	}
	if err != nil {
		fmt.Println("error")
		return
	}
	// js跳转
	for i := 0; i < 3; i++ {
		jumpurl := Urljump(resp)
		if jumpurl == "" {
			break
		}
		resp, err = r.reqClient.R().Get(jumpurl)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	if err != nil {
		return
	}
	data := ReadfromJson()
	result = &Result{
		Url:           resp.Request.URL.Scheme + "://" + resp.Request.URL.Host,
		StatusCode:    resp.StatusCode,
		ContentLength: len(resp.String()),
		Title:         GetTitle(resp),
		Fingers:       r.getFinger(resp, data),
	}
	if !r.options.NoIconhash {
		result.Favicon, result.IconHash = r.getFavicon(resp)
	}

	if !r.options.NoWappalyzer {
		result.Wappalyzer = r.wappalyzerClient.Fingerprint(resp.Header, resp.Bytes())
	}

	return

}
