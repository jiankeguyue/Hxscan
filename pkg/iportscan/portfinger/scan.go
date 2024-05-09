package portfinger

import (
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/proxy"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	Scanner *NmapProbe
	Proxy   string
}

type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

type Extras struct {
	ServiceName     string
	VendorProduct   string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	CPE             string
	Sign            string
}

type Address struct {
	IP   string
	Port string
}

func NewEngine(proxy string, scanner *NmapProbe) (*Engine, error) {
	return &Engine{
		Scanner: scanner,
		Proxy:   proxy,
	}, nil
}

func (e *Engine) Run(targets map[string][]int) []*Result {
	var results []*Result
	// 并发开启扫描
	wg := &sync.WaitGroup{}
	taskChan := make(chan Address, 200)
	// 动态分配，后面就是一个一个等待扫描完成，避免造成通道堵塞
	for i := 0; i < 200; i++ {
		go func() {
			for task := range taskChan {
				resp := e.Scanner.ScanWithProbe(task.IP, task.Port, e.Proxy, 5)
				if resp.ServiceName != "" {
					gologger.Info().Msgf("Result : [%v] -> (协议：%v)(产品：%v)(版本：%v)(探针：%v)", resp.Addr, resp.ServiceName, resp.VendorProduct, resp.Version, resp.ProbeName)
					results = append(results, resp)
				}
				wg.Done()
			}
		}()
	}

	for ip, ports := range targets {
		for _, port := range ports {
			addr := Address{
				IP:   ip,
				Port: strconv.Itoa(port),
			}
			wg.Add(1)
			taskChan <- addr
		}
	}
	wg.Wait()
	close(taskChan)
	return results
}

func (N *NmapProbe) ScanWithProbe(host, port, proxyAddr string, SocketTimeout int) *Result {
	gologger.Debug().Msgf("gggg")
	var defaultProbe []int // 保存默认端口对应的协议索引
	var oneProbe []int     // 保存优先级为一对应的协议索引
	var sixProbe []int     // 保存优先级小于6对应的协议索引
	var nineProbe []int    // 保存剩余对应的协议索引
	var excludeIndex []int // 保存排除的协议索引

	for i := 0; i < len(N.Probes); i++ {
		for _, v := range N.Probes[i].Ports {
			_, ok := v[port]
			if ok {
				defaultProbe = append(defaultProbe, i)
				excludeIndex = append(excludeIndex, i)
				break
			}
		}

		if N.Probes[i].Rarity == 1 && !IsExclude(excludeIndex, i) {
			oneProbe = append(oneProbe, i)
		}

		if N.Probes[i].Rarity != 1 && N.Probes[i].Rarity < 6 && !IsExclude(excludeIndex, i) {
			sixProbe = append(sixProbe, i)
		}

		if N.Probes[i].Rarity >= 6 && !IsExclude(excludeIndex, i) {
			nineProbe = append(nineProbe, i)
		}
	}

	if len(defaultProbe) > 0 {
		wg := sync.WaitGroup{}
		chanResult := make(chan *Result, len(defaultProbe))
		for _, i := range defaultProbe {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				N.ResultSocket(GetAddress(host, port), proxyAddr, v, SocketTimeout, chanResult)
			}(i)
		}
		wg.Wait()
		close(chanResult)
		for resp := range chanResult {
			gologger.Debug().Msgf("[+] 固定默认端口指纹获取成功:%s:%s -> %s", host, port, resp.ServiceName)
			return resp
		}
	}

	if len(oneProbe) > 0 {
		gologger.Debug().Msg("探测等级等于1的协议")
		wg := sync.WaitGroup{}
		chanResult := make(chan *Result, len(oneProbe))
		for _, i := range oneProbe {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				N.ResultSocket(GetAddress(host, port), proxyAddr, v, SocketTimeout, chanResult)
			}(i)
		}
		wg.Wait()
		close(chanResult)
		for resp := range chanResult {
			gologger.Debug().Msgf("[+] 級別1端口指纹获取成功:%s:%s -> %s", host, port, resp.ServiceName)
			return resp
		}
	}

	if len(sixProbe) > 0 {
		gologger.Debug().Msg("探测等级小于6的协议")
		wg := sync.WaitGroup{}
		chanResult := make(chan *Result, len(sixProbe))
		for _, i := range sixProbe {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				N.ResultSocket(GetAddress(host, port), proxyAddr, v, SocketTimeout, chanResult)
			}(i)
		}
		wg.Wait()
		close(chanResult)
		for resp := range chanResult {
			gologger.Debug().Msgf("[+] 级别<6指纹获取成功:%s:%s %s", host, port, resp.ServiceName)
			return resp
		}
	}

	// 并发探测剩下等级的协议
	if len(nineProbe) > 0 {
		wg := sync.WaitGroup{}
		chanResult := make(chan *Result, len(nineProbe))
		for _, i := range nineProbe {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				N.ResultSocket(GetAddress(host, port), proxyAddr, v, SocketTimeout, chanResult)
			}(i)
		}
		wg.Wait()
		close(chanResult)
		for resp := range chanResult {
			gologger.Debug().Msgf("[+] 级别<9指纹获取成功:%s:%s %s", host, port, resp.ServiceName)
			return resp
		}
	}

	gologger.Debug().Msgf("[--] 未知服务: %s: %s", host, port)
	Resulttmp := Result{}
	Resulttmp.Addr = GetAddress(host, port)
	return &Resulttmp

}

func (N *NmapProbe) grabResponse(addr, proxyAddr string, Indexes, SocketTimeout int) ([]byte, error) {
	var response []byte
	var err error
	var dialer proxy.Dialer
	var conn net.Conn
	connTimeout := time.Duration(int64(SocketTimeout)) * time.Second
	if proxyAddr != "" {
		dialer, err = proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{Timeout: connTimeout})
		if err != nil {
			return nil, err
		}
		conn, err = dialer.Dial("tcp", addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, connTimeout)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return nil, err
	}
	gologger.Debug().Msgf("请求数据： %v", string(N.Probes[Indexes].Data))

	if len(N.Probes[Indexes].Data) > 0 {
		err = conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(int64(SocketTimeout))))
		if err != nil {
			return nil, err
		}
		_, errWrite := conn.Write(N.Probes[Indexes].Data)
		if errWrite != nil {
			return nil, errWrite
		}
	}

	err = conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(int64(SocketTimeout))))
	if err != nil {
		return nil, err
	}

	for {
		buff := make([]byte, 1024)
		n, errRead := conn.Read(buff)
		if errRead != nil {
			if len(response) > 0 {
				break
			} else {
				return nil, errRead
			}
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}
	gologger.Debug().Msgf("resp data: %v", string(response))
	return response, nil
}

// 给通道发送任务，匹配后进行返回
func (N *NmapProbe) ResultSocket(address, proxyAddr string, Indexes, SocketTimeout int, ResultChan chan *Result) {
	responseData, err := N.grabResponse(address, proxyAddr, Indexes, SocketTimeout)
	if err != nil {
		return
	}
	ok, extras := N.regexResponse(responseData, N.Probes[Indexes].Matches, N.Probes[Indexes].Fallback)
	if !ok {
		return
	}
	ResultChan <- &Result{
		Addr:          address,
		ServiceName:   extras.ServiceName,
		ProbeName:     N.Probes[Indexes].Name,
		VendorProduct: extras.VendorProduct,
		Version:       extras.Version,
	}

}

func (N *NmapProbe) regexResponse(response []byte, matchtmp []*Match, Fallback string) (bool, *Extras) {
	extras := Extras{}
	if len(response) > 0 {
		for _, match := range matchtmp {
			matched := match.MatchPattern(response)
			if matched && !match.IsSoft {
				extras = match.ParseVersionInfo(response)
				extras.ServiceName = match.Service
				return true, &extras
			}
		}
		// 前面都匹配不了就用fallback替补探针
		if _, ok := N.ProbeMapKeyName[Fallback]; ok {
			secondProbe := N.ProbeMapKeyName[Fallback]
			for _, match := range secondProbe.Matches {
				matched := match.MatchPattern(response)
				if matched && !match.IsSoft {
					extras = match.ParseVersionInfo(response)
					extras.ServiceName = match.Service
					return true, &extras
				}
			}
		}

	}
	return false, &extras
}

func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string([]rune(string(response))) //将字节切片转化成string字符串类型
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	foundItems = foundItems[1:]
	versionInfo := m.VersionInfo
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}

func IsExclude(m []int, value int) bool {
	for _, v := range m {
		if v == value {
			return true
		}
	}
	return false
}

func GetAddress(ip, port string) string {
	return ip + ":" + port
}
