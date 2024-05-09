package whereip

import (
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/projectdiscovery/gologger"
	"sitescan/internal/utils"
	"strings"
)

type whereResult struct {
	Country  string
	Province string
	City     string
	Supplier string
}

func Query(ip string) (parseResult *whereResult, err error) {
	if ip == "" {
		return
	}

	searcher, err := xdb.NewWithFileOnly(utils.DbPath)

	if err != nil {
		gologger.Debug().Msgf("IP查询失败: %s -> %v", ip, err)
		return nil, err
	}

	region, err := searcher.SearchByStr(ip)

	if err != nil {
		gologger.Debug().Msgf("IP查询失败: %s -> %v", ip, err)
		return nil, err
	}

	parseResult = parseResponse(region)
	return parseResult, nil
}

func parseResponse(region string) (result *whereResult) {
	parts := strings.Split(region, "|")
	result = &whereResult{
		Country:  parts[0],
		Province: parts[2],
		City:     parts[3],
		Supplier: parts[4],
	}
	return
}
