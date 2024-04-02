package cmd

import (
	"encoding/json"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
	"sitescan/internal/utils"
	"sitescan/pkg/sitescan"
)

type SitescanOptions struct {
	Threads      int
	Timeout      int
	Proxy        string
	Headers      []string
	NoIconhash   bool
	NoShiro      bool
	NoWappalyzer bool
}

var (
	sitescanOptions SitescanOptions
)

var sitescanCmd = &cobra.Command{
	Use:   "sitescan",
	Short: "web站点常规信息收集",
	Long:  "web站点信息收集,获取状态码、标题、指纹等",
	Run: func(cmd *cobra.Command, args []string) {

		if err := sitescanOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		sitescanOptions.run()
	},
}

func (o *SitescanOptions) configureOptions() error {
	if o.Proxy == "bp" {
		o.Proxy = "http://127.0.0.1:8080"
	}

	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("webscanOptions: %v", string(opt))

	return nil
}

func init() {
	sitescanCmd.Flags().IntVar(&sitescanOptions.Threads, "threads", 10, "线程数 number of threads")
	sitescanCmd.Flags().IntVar(&sitescanOptions.Timeout, "timeout", 10, "超时数 若网络响应慢则设置大一点  timeout time")
	sitescanCmd.Flags().StringVarP(&sitescanOptions.Proxy, "proxy", "p", "", "可与bp梦幻联动  proxy(example: -p 'http://127.0.0.1:8080' | -p bp)")
	sitescanCmd.Flags().StringSliceVar(&sitescanOptions.Headers, "headers", []string{}, "add custom headers(example: --headers 'User-Agent: xxx,Cookie: xxx')")

	sitescanCmd.Flags().BoolVar(&sitescanOptions.NoIconhash, "no-iconhash", false, "默认扫描 icohash mmh32hash ")
	sitescanCmd.Flags().BoolVar(&sitescanOptions.NoShiro, "no-shiro", false, "默认扫描 shiro 框架 not scan shiro")
	sitescanCmd.Flags().BoolVar(&sitescanOptions.NoWappalyzer, "no-wappalyzer", false, "默认对接wappalyzer指纹库 not scan wappalyzer")

	rootCmd.AddCommand(sitescanCmd)
}

func (o *SitescanOptions) run() {
	options := &sitescan.Options{
		Proxy:        o.Proxy,
		Threads:      o.Threads,
		Timeout:      o.Timeout,
		Headers:      o.Headers,
		NoColor:      commonOptions.NoColor,
		NoShiro:      o.NoShiro,
		NoIconhash:   o.NoIconhash,
		NoWappalyzer: o.NoWappalyzer,
	}
	siteRunner, err := sitescan.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("webscan.NewRunner() err, %v", err)
		return
	}
	results := siteRunner.Run(targets)
	if len(results) == 0 {
		gologger.Info().Msgf("结果为空")
		return
	}
	gologger.Info().Msgf("存活数量: %v", len(results))
	// 保存 webscan 结果
	if commonOptions.ResultFile != "" {
		err = utils.SaveMarshal(commonOptions.ResultFile, results)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
			return
		}
	}
}
