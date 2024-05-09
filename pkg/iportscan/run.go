package iportscan

import (
	"context"
	"github.com/projectdiscovery/gologger"
	//"github.com/suryatmodulus/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	// "github.com/jiankeguyue/nabbu-early/v2/pkg/runner"
	"sitescan/pkg/iportscan/nabbu"
	"sitescan/pkg/iportscan/portfinger"
	"sitescan/pkg/iportscan/webiport"
	"time"
)

type Ip struct {
	Ip       string
	Ports    string
	Country  string
	Province string
	City     string
	Supplier string
	OS       string
}

type Service struct {
	Address  string
	Protocol string
	Version  string
}

type Options struct {
	Hosts     []string
	PortRange string
	Rate      int
	Threads   int
	Proxy     string
	MaxPort   int
	Process   bool
	NmapProbe *portfinger.NmapProbe
}

type Runner struct {
	options          *Options
	naabuRunner      *runner.Runner
	portFingerEngine *portfinger.Engine
}

func NewRunner(options *Options) (*Runner, error) {
	naabuRunner, err := nabbu.NewRunner(options.Hosts, options.PortRange, options.Rate, options.Threads, options.Proxy, options.Process)
	if err != nil {
		return nil, err
	}
	portFingerEngine, err := portfinger.NewEngine(options.Proxy, options.NmapProbe)
	if err != nil {
		return nil, err
	}
	return &Runner{
		options:          options,
		naabuRunner:      naabuRunner,
		portFingerEngine: portFingerEngine,
	}, nil
}

func (r *Runner) Run() (results []*portfinger.Result) {
	start := time.Now()
	gologger.Info().Msgf("开始端口扫描, 存活如下")
	defer r.naabuRunner.Close()

	err := r.naabuRunner.RunEnumeration(context.TODO())
	if err != nil {
		gologger.Error().Msgf("naabuRunner.RunEnumeration() err, %v", err)
		return
	}

	gologger.Info().Msgf("开放端口的host数目: %v", len(nabbu.Results))
	if len(nabbu.Results) == 0 {
		return
	}
	naabuResults := nabbu.Results
	for k := range naabuResults {
		if len(naabuResults[k]) > r.options.MaxPort {
			gologger.Info().Msgf("%v 开放端口大于 %v", k, r.options.MaxPort)
			// 如果端口开放大于 max-port，进行 web 探活
			naabuResults[k] = webiport.Run(k, 1, 50, "")
		}
	}
	gologger.Info().Msgf("端口开放扫描完成: %v", time.Since(start))
	// 开放的端口使用nmap指纹识别
	gologger.Info().Msgf("端口协议识别中...")
	results = r.portFingerEngine.Run(naabuResults)
	gologger.Info().Msgf("端口协议扫描完成: %v", time.Since(start))
	return
}
