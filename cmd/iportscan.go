package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
	"sitescan/internal/utils"
	"sitescan/pkg/iportscan"
	"sitescan/pkg/iportscan/portfinger"
	"sitescan/pkg/iportscan/whereip"
	"sitescan/pkg/sitescan"
	"strings"
)

type iportscanOptions struct {
	Proxy     string
	PortRange string
	Rate      int
	Threads   int
	Process   bool
	MaxPort   int
	Os        bool
	Addr      bool
}

var iportscanoptions iportscanOptions

func init() {
	iportscanCmd.Flags().StringVarP(&iportscanoptions.PortRange, "port-range", "p", "21,22,53,80,443,445,1433,3306,3389,8080", "port range(example: -p '22,80-90,1433,3306')")
	iportscanCmd.Flags().StringVar(&iportscanoptions.Proxy, "proxy", "", "socks5 proxy, (example: --proxy 192.168.31.227:47871')")
	iportscanCmd.Flags().IntVar(&iportscanoptions.Rate, "rate", 1500, "packets to send per second")
	iportscanCmd.Flags().IntVar(&iportscanoptions.Threads, "threads", 25, "number of threads")
	iportscanCmd.Flags().IntVar(&iportscanoptions.MaxPort, "max-port", 200, "discard result if it more than max port")
	iportscanCmd.Flags().BoolVar(&iportscanoptions.Process, "process", false, "show process")
	iportscanCmd.Flags().BoolVar(&iportscanoptions.Os, "os", false, "check os")
	iportscanCmd.Flags().BoolVar(&iportscanoptions.Addr, "addr", false, "get addr")

	//ipscanCmd.Flags().BoolVar(&ipscanOptions.Crack, "crack", false, "open crack")
	//ipscanCmd.Flags().BoolVar(&ipscanOptions.Pocscan, "pocscan", false, "open pocscan")

	rootCmd.AddCommand(iportscanCmd)
}

var iportscanCmd = &cobra.Command{
	Use:   "iportscan",
	Short: "IP 端口扫描",
	Long:  "IP 端口扫描, 自动调动之前的sitescan. 后续会出更多联动功能",
	Run: func(cmd *cobra.Command, args []string) {
		if err := iportscanoptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		//if err := initFinger(); err != nil {
		//	gologger.Error().Msgf("initFinger() err, %v", err)
		//}

		if err := initNmapProbe(); err != nil {
			gologger.Fatal().Msgf("initNmapProbe() err, %v", err)
		}

		if err := iportscanoptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		iportscanoptions.run()
	},
}

var nmapProbe portfinger.NmapProbe

func (o *iportscanOptions) validateOptions() error {
	return nil
}

func (o *iportscanOptions) configureOptions() error {
	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("当前选项配置: %v", string(opt))
	return nil
}

func initNmapProbe() error {
	nmapData, err := utils.ReadFile("nmap.txt")
	if err != nil {
		return err
	}
	err = nmapProbe.Init(nmapData)
	if err != nil {
		return nil
	}

	if err != nil {
		return nil
	}
	return nil
}

func (o *iportscanOptions) run() {
	var hosts []string
	for _, target := range targets {
		tmpHosts, err := iportscan.ParseIP(target)
		if err != nil {
			return
		}
		hosts = append(hosts, tmpHosts...)
	}

	options := &iportscan.Options{
		Hosts:     hosts,
		PortRange: o.PortRange,
		MaxPort:   o.MaxPort,
		Process:   o.Process,
		Rate:      o.Rate,
		Threads:   o.Threads,
		NmapProbe: &nmapProbe,
		Proxy:     o.Proxy,
	}

	iportscanRunner, err := iportscan.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("New runner出错： %v", err)
		return
	}

	var ipResults []*iportscan.Ip
	var serviceResults []*iportscan.Service
	for _, ip := range hosts {
		ipResult := &iportscan.Ip{
			Ip: ip,
		}

		if o.Addr {
			whereResults, err := whereip.Query(ip)
			if err != nil {
				gologger.Error().Msgf("ipscanRunner.GetAddr() err, %v", err)
				return
			}
			ipResult.Country = whereResults.Country
			ipResult.City = whereResults.City
			ipResult.Province = whereResults.Province
			ipResult.Supplier = whereResults.Supplier
		}

		if o.Os {
			if ipResult.OS, err = iportscan.CheckOS(ip); err != nil {
				gologger.Error().Msgf("ipscan.CheckOS() err, %v", err)
				return
			}
		}
		if o.Addr || o.Os {
			gologger.Info().Msgf("%v [%v %v %v %v] [%v]", ipResult.Ip, ipResult.Country, ipResult.Province, ipResult.City, ipResult.Supplier, ipResult.OS)
		}
		ipResults = append(ipResults, ipResult)
	}
	//  进入最关键的端口扫描，希望不会敲错逻辑》。。
	portscanResults := iportscanRunner.Run()
	if len(portscanResults) == 0 {
		gologger.Info().Msgf("ggg, 端口扫描结果为空")
		return
	}
	ipPortMap := make(map[string][]string)

	// 建立映射
	for _, result := range portscanResults {
		t := strings.Split(result.Addr, ":")
		ip := t[0]
		port := t[1]
		ipPortMap[ip] = append(ipPortMap[ip], port)
	}
	for _, ipResult := range ipResults {
		ipResult.Ports = strings.Join(ipPortMap[ipResult.Ip], ",")
	}
	// 结果处理
	var webTargets []string
	for _, portscanResult := range portscanResults {
		t := strings.Split(portscanResult.Addr, ":")
		ip := t[0]
		port := t[1]
		// unknown 服务也使用 webscan
		if portscanResult.ServiceName == "ssl" {
			if port == "443" {
				webTargets = append(webTargets, "https://"+ip)
			} else {
				webTargets = append(webTargets, "https://"+ip+":"+port)
			}
		} else if portscanResult.ServiceName == "http" {
			if port == "80" {
				webTargets = append(webTargets, "http://"+ip)
			} else {
				webTargets = append(webTargets, "http://"+ip+":"+port)
			}
		} else if portscanResult.ServiceName == "unknown" {
			webTargets = append(webTargets, ip+":"+port)
		} else {
			serviceResults = append(serviceResults, &iportscan.Service{
				Address:  portscanResult.Addr,
				Protocol: portscanResult.ServiceName,
				Version:  fmt.Sprintf("%v %v", portscanResult.VendorProduct, portscanResult.Version),
			})
		}
	}
	// 保存 ipscan 结果
	if commonOptions.ResultFile != "" {
		err = utils.SaveMarshal(commonOptions.ResultFile, ipResults)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
		}
	}
	gologger.Info().Msgf("web探测: %v", len(webTargets))
	gologger.Info().Msgf("service探测: %v", len(serviceResults))
	fmt.Println("\n")
	fmt.Println("\n")
	// webscan
	options2 := &sitescan.Options{
		Threads: sitescanOptions.Threads,
		Timeout: sitescanOptions.Timeout,
		Headers: sitescanOptions.Headers,
		NoColor: commonOptions.NoColor,
	}
	if iportscanoptions.Proxy != "" {
		options.Proxy = "socks5://" + iportscanoptions.Proxy
	}
	webscanRunner, err := sitescan.NewRunner(options2)
	if err != nil {
		gologger.Error().Msgf("webscan.NewRunner() err, %v", err)
		return
	}
	webscanResults := webscanRunner.Run(webTargets)
	if len(webscanResults) == 0 {
		gologger.Info().Msgf("web扫描结果为空")
		return
	}
	gologger.Info().Msgf("存活数量: %v", len(webscanResults))

}
