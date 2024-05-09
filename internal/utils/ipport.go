package utils

import (
	"fmt"
	"strconv"
	"strings"
)

const portListStrParts = 2

func ParsePortsList(data string) (map[int]struct{}, error) {
	ports := make(map[int]struct{})
	ranges := strings.Split(data, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != portListStrParts {
				return nil, fmt.Errorf("输入参数存在问题，请仔细校验：1-60000")
			}

			port1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("第一个端口参数输入有问题，请仔细进行校验")
			}

			port2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("第二个端口参数输入有问题，请仔细进行校验")
			}

			if port1 > port2 {
				return nil, fmt.Errorf("第一个端口参数大于第二个端口参数，请仔细进行校验")
			}

			for i := port1; i <= port2; i++ {
				ports[i] = struct{}{}
			}

		} else {
			port, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("端口参数输入有问题，请仔细进行校验")
			}
			ports[port] = struct{}{}

		}
	}

	return ports, nil
}
