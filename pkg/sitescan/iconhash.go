package sitescan

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/twmb/murmur3"
)

func (r *siteRunner) GetHash(url string) (iconhash string) {
	content, err := r.FromURLGetContent(url)
	if err != nil {
		return
	}

	if len(content) > 0 {
		iconhash = Mmh3Hash32(Base64(content))
	}
	return
}

func (r *siteRunner) FromURLGetContent(url string) (content []byte, err error) {
	resp, err := r.reqClient.R().Get(url)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("favicon url %v status code is not 200", url)
	}
	content = resp.Bytes()
	return
}

func (r *siteRunner) FromRespGetContent(resp *req.Response) (content []byte, err error) {
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("favicon response status code is not 200")
	}
	content = resp.Bytes()
	return
}

func Mmh3Hash32(raw []byte) string {
	var hash32 = murmur3.New32()
	hash32.Write(raw)
	return fmt.Sprintf("%d", int32((hash32.Sum32())))
}

func Base64(raw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(raw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
