package goaccessfmt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/taoky/goaccessfmt/pkg/goaccessfmt"
)

var location = time.FixedZone("UTC+8", 8*60*60)

func TestCombined(t *testing.T) {
	logfmt, datefmt, timefmt, err := goaccessfmt.GetFmtFromPreset("combined")
	if err != nil {
		t.Error(err)
	}
	conf, err := goaccessfmt.SetupConfig(logfmt, datefmt, timefmt, location)
	if err != nil {
		t.Error(err)
	}

	logitem := goaccessfmt.GLogItem{}
	line := `114.5.1.4 - - [11/Jun/2023:11:23:45 +0800] "GET /example/path/file.img HTTP/1.1" 429 568 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"`
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		t.Error(err)
	}
	expectedLogitem := goaccessfmt.GLogItem{
		Host:     "114.5.1.4",
		Date:     "20230611",
		Time:     "11:23:45",
		Dt:       time.Date(2023, time.Month(6), 11, 11, 23, 45, 0, location),
		Req:      "/example/path/file.img",
		Status:   429,
		RespSize: 568,
		Ref:      "-",
		Agent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
	}
	if !reflect.DeepEqual(logitem, expectedLogitem) {
		t.Errorf("want (%v), get (%v)", expectedLogitem, logitem)
	}
}

func TestCaddy(t *testing.T) {
	logfmt, datefmt, timefmt, err := goaccessfmt.GetFmtFromPreset("caddy")
	if err != nil {
		t.Error(err)
	}
	conf, err := goaccessfmt.SetupConfig(logfmt, datefmt, timefmt, location)
	if err != nil {
		t.Error(err)
	}

	logitem := goaccessfmt.GLogItem{}
	line := `{"level":"info","ts":1646861401.5241024,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"41342","client_ip":"127.0.0.1","proto":"HTTP/2.0","method":"GET","host":"localhost","uri":"/","headers":{"User-Agent":["curl/7.82.0"],"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"example.com"}},"bytes_read": 0,"user_id":"","duration":0.000929675,"size":10900,"status":200,"resp_headers":{"Server":["Caddy"],"Content-Encoding":["gzip"],"Content-Type":["text/html; charset=utf-8"],"Vary":["Accept-Encoding"]}}`
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		t.Error(err)
	}
	expectedLogitem := goaccessfmt.GLogItem{
		Host:      "127.0.0.1",
		Date:      "20220309",
		Time:      "21:30:01",
		Dt:        time.Date(2022, 3, 9, 21, 30, 1, 0, location),
		VHost:     "localhost",
		Method:    "GET",
		Req:       "/",
		Protocol:  "HTTP/2",
		Status:    200,
		RespSize:  10900,
		Agent:     "curl/7.82.0",
		ServeTime: 929,
		TLSCypher: "4865",
		TLSType:   "h2",
		MimeType:  "text/html; charset=utf-8",
	}
	if !reflect.DeepEqual(logitem, expectedLogitem) {
		t.Errorf("want (%v), get (%v)", expectedLogitem, logitem)
	}
}
