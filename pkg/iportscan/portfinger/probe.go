package portfinger

import (
	"github.com/projectdiscovery/gologger"
	"regexp"
	"sitescan/internal/utils"
	"strconv"
	"strings"
)

type NmapProbe struct {
	Probes          []*Probe
	ProbeMapKeyName map[string]*Probe
}

type Probe struct {
	Name     string              // 探针名称
	Ports    []map[string]string // 该探针默认端口
	Data     []byte              // socket发送的数据
	Fallback string              // 如果探针匹配项没有匹配到，则使用Fallback指定的探针作为备用
	Matches  []*Match            // 正则协议内容
	Rarity   int                 // 指纹探测等级
}

type Match struct {
	IsSoft          bool
	Service         string
	Pattern         string
	VersionInfo     string
	PatternCompiled *regexp.Regexp
}

func (Np *NmapProbe) Init(nmapData []byte) error {
	nmapStr := string(nmapData)
	Np.parseProbesFromContent(&nmapStr)
	Np.parseProbesToMapKeyName()
	return nil
}

// Count 统计指纹库中正则条数
func (Np *NmapProbe) Count() int {
	count := 0
	for _, probe := range Np.Probes {
		count += len(probe.Matches)
	}
	return count
}

// 把probe变成键值对
func (Np *NmapProbe) parseProbesToMapKeyName() {
	var probesMap = map[string]*Probe{}
	for _, probe := range Np.Probes {
		probesMap[probe.Name] = probe
	}
	Np.ProbeMapKeyName = probesMap
}

// 需要解析nmap指纹库进行处理
func (Np *NmapProbe) parseProbesFromContent(content *string) {
	var probes []*Probe
	var lines []string
	linesTemp := strings.Split(*content, "\n")

	// 过滤多余东西，取其精华去其糟粕
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}
	if len(lines) == 0 {
		gologger.Debug().Msgf("[error] 端口扫描对应的Nmap指纹库为空\n")
	}

	// 判断指纹库中的exclude标识
	num := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			num += 1
		}
		if num > 1 {
			gologger.Debug().Msgf("[error] [端口扫描] nmap指纹库格式错误，Exclude标识符过多或不在开头")
		}
	}
	firstProbe := lines[0]
	if !(strings.HasPrefix(firstProbe, "Exclude ") || strings.HasPrefix(firstProbe, "probe ")) {
		gologger.Debug().Msgf("[error] [端口扫描] namp指纹库解析失败，首行应由Exclude和Probe开头")
	}

	if num == 1 {
		lines = lines[1:]
	}

	fcontent := strings.Join(lines, "\n")
	fcontent = "\n" + fcontent
	probeParts := strings.Split(fcontent, "\nProbe")
	// \nProbe TCP RTSPRequest q|OPTIONS / RTSP/1.0\r\n\r\n|
	// 第一个部分通常是从字符串的开头到第一个探针标识符 \nProbe 之间的内容,TCP RTSPRequest q|OPTIONS / RTSP/1.0\r\n\r\n|
	probeParts = probeParts[1:]

	for _, probePart := range probeParts {
		probe := Probe{}
		probe.fromString(&probePart)
		probes = append(probes, &probe)
	}

	Np.Probes = probes
}

// 解析每个probe探针的标识符数据
func (p *Probe) fromString(data *string) {
	fdata := strings.TrimSpace(*data)
	lines := strings.Split(fdata, "\n")

	// 存在疑惑，需要解析nmap原始数据
	probeStr := lines[0]

	p.parseProbeInfo(probeStr)

	var matches []*Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matches = append(matches, &match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matches = append(matches, &softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			p.parsePorts(line)
		} else if strings.HasPrefix(line, "fallback ") {
			p.parseFallback(line)
		} else if strings.HasPrefix(line, "rarity ") {
			p.parseRarity(line)
		}
	}
	p.Matches = matches

}

func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:4]
	other := probeStr[4:]
	if !(proto == "TCP " || proto == "UDP ") {
		gologger.Debug().Msgf("[error] [端口扫描] 解析nmap指纹库失败，protocol字段不为UDP和TCP")
	}
	if len(other) == 0 {
		gologger.Debug().Msgf("[error] [端口扫描] 解析nmap指纹库失败，protocol描述字段为空")
	}

	directive := p.getDirectiveSyntax(other)
	p.Name = directive.DirectiveName
	dataList := strings.Split(directive.DirectiveStr, directive.Delimiter)

	if len(dataList) > 0 {
		dataByte, err := utils.DecodeChaoData(dataList[0])
		if err != nil {
			gologger.Debug().Msgf("[error] [端口扫描] nmap指纹库编码发送包失败[%s]:  %s\n", dataList[0], err)
		} else {
			p.Data = dataByte
		}
	}

}

// 解析 probe 的阐述字段，示例如下 Probe TCP RTSPRequest q|OPTIONS / RTSP/1.0\r\n\r\n|
func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}
	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]
	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr
	return directive
}

func (p *Probe) getMatch(data string) (match Match, err error) {
	match = Match{}
	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")

	patternUnescaped, _ := utils.DecodePattern(pattern)
	patternUnescapedStr := string(patternUnescaped)
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return match, ok
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	return match, nil

}

func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")
	patternUnescaped, _ := utils.DecodePattern(pattern)
	patternUnescapedStr := string(patternUnescaped)
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return softMatch, ok
	}

	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

func (p *Probe) parsePorts(data string) {
	data1 := strings.Replace(data, "ports ", "", -1)
	if strings.Contains(data1, ",") { // 是否为多个端口
		strlist := strings.Split(data1, ",")
		for _, v := range strlist {
			p.Ports = append(p.Ports, map[string]string{v: ""})
		}
	} else {
		p.Ports = []map[string]string{{data1: ""}}
	}
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(data[len("rarity")+1:])
}
