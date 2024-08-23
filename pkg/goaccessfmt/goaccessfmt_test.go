package goaccessfmt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/taoky/goaccessfmt/pkg/goaccessfmt"
)

// goaccess would NOT parse timezone
// user needs to set a fixed timezone themselves
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
		Method:   "GET",
		Protocol: "HTTP/1.1",
	}
	if !reflect.DeepEqual(logitem, expectedLogitem) {
		t.Errorf("want (%v), get (%v)", expectedLogitem, logitem)
	}

	// Test some weird log
	line =
		`114.5.1.4 - - [04/Apr/2024:08:01:12 +0800] "\x16\x03\x01\x00\xCA\x01\x00\x00\xC6\x03\x03\x94b\x22\x06u\xBEi\xF6\xC5cA\x97eq\xF0\xD5\xD3\xE6\x08I" 400 163 "-" "-"`
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		t.Error(err)
	}
	expectedLogitem = goaccessfmt.GLogItem{
		Host:     "114.5.1.4",
		Date:     "20240404",
		Time:     "08:01:12",
		Dt:       time.Date(2024, time.Month(4), 4, 8, 1, 12, 0, location),
		Req:      `\x16\x03\x01\x00\xCA\x01\x00\x00\xC6\x03\x03\x94b\x22\x06u\xBEi\xF6\xC5cA\x97eq\xF0\xD5\xD3\xE6\x08I`,
		Status:   400,
		RespSize: 163,
		Ref:      "-",
		Agent:    "-",
		Method:   "",
		Protocol: "",
	}
	if !reflect.DeepEqual(logitem, expectedLogitem) {
		t.Errorf("want (%v), get (%v)", expectedLogitem, logitem)
	}
	line = `114.5.1.5 - - [04/Apr/2024:09:02:13 +0800] "\x16\x03\x01\x00\xEE\x01\x00\x00\xEA\x03\x03\x9C\xB4\x92\xC5{\xE9\xEC\x18\xB1\x17\x04f\xCA\x0F\xF3\xFD\xAA\x98H\xA5N\xBC\xC9\xD7\xF8\x95.H\x15\x13\xF2\xF9 ~W\xB9\x94Qs\x01\x02\xE3c'\xA8pB\xC5\xCC\x10c\xC9\xF4\x99{\x0E1\x90\x81\xBD4J\x10y\x17\x00&\xC0+\xC0/\xC0,\xC00\xCC\xA9\xCC\xA8\xC0\x09\xC0\x13\xC0" 400 163 "-" "-"`
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		t.Error(err)
	}
	expectedLogitem = goaccessfmt.GLogItem{
		Host: "114.5.1.5",
		Date: "20240404",
		Time: "09:02:13",
		Dt:   time.Date(2024, time.Month(4), 4, 9, 2, 13, 0, location),
		// golang url.QueryUnescape would convert + to space
		Req:      `\x16\x03\x01\x00\xEE\x01\x00\x00\xEA\x03\x03\x9C\xB4\x92\xC5{\xE9\xEC\x18\xB1\x17\x04f\xCA\x0F\xF3\xFD\xAA\x98H\xA5N\xBC\xC9\xD7\xF8\x95.H\x15\x13\xF2\xF9 ~W\xB9\x94Qs\x01\x02\xE3c'\xA8pB\xC5\xCC\x10c\xC9\xF4\x99{\x0E1\x90\x81\xBD4J\x10y\x17\x00&\xC0 \xC0/\xC0,\xC00\xCC\xA9\xCC\xA8\xC0\x09\xC0\x13\xC0`,
		Status:   400,
		RespSize: 163,
		Ref:      "-",
		Agent:    "-",
		Method:   "",
		Protocol: "",
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

func TestXFF(t *testing.T) {
	logfmt := `~h{ } %^[%d:%t %^] "%r" %s %b "%R" "%u"`
	datefmt := "%d/%b/%Y"
	timefmt := "%T"
	conf, err := goaccessfmt.SetupConfig(logfmt, datefmt, timefmt, location)
	if err != nil {
		t.Error(err)
	}

	logitem := goaccessfmt.GLogItem{}
	line := `114.5.1.4 191.9.81.0 - - [31/May/2018:00:00:00 +0800] "GET http://example.com/test HTTP/1.1" 200 409 "-" "Dalvik/2.1.0 (Linux; U; Android 8.0.0; ONEPLUS A5010 Build/OPR1.170623.032)"`
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		t.Error(err)
	}
	expectedLogitem := goaccessfmt.GLogItem{
		Host:     "114.5.1.4",
		Date:     "20180531",
		Time:     "00:00:00",
		Dt:       time.Date(2018, 5, 31, 0, 0, 0, 0, location),
		Req:      "http://example.com/test",
		Agent:    "Dalvik/2.1.0 (Linux; U; Android 8.0.0; ONEPLUS A5010 Build/OPR1.170623.032)",
		Method:   "GET",
		Protocol: "HTTP/1.1",
		Status:   200,
		RespSize: 409,
		Ref:      "-",
	}
	if !reflect.DeepEqual(logitem, expectedLogitem) {
		t.Errorf("want (%v), get (%v)", expectedLogitem, logitem)
	}
}

func TestServerExtension(t *testing.T) {
	// logfmt := goaccessfmt.Logs.Caddy
	logfmt := `{ "server": "%S", "ts": "%x.%^", "request": { "client_ip": "%h", "proto":"%H", "method": "%m", "host": "%v", "uri": "%U", "headers": {"User-Agent": ["%u"], "Referer": ["%R"] }, "tls": { "cipher_suite":"%k", "proto": "%K" } }, "duration": "%T", "size": "%b","status": "%s", "resp_headers": { "Content-Type": ["%M"] } }`
	datefmt := goaccessfmt.Dates.Sec
	timefmt := goaccessfmt.Times.Sec
	conf, err := goaccessfmt.SetupConfig(logfmt, datefmt, timefmt, location)
	if err != nil {
		t.Error(err)
	}
	logitem := goaccessfmt.GLogItem{}
	line := `{"level":"info","ts":1646861401.5241024,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"41342","client_ip":"127.0.0.1","proto":"HTTP/2.0","method":"GET","host":"localhost","uri":"/","headers":{"User-Agent":["curl/7.82.0"],"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"example.com"}},"bytes_read": 0,"user_id":"","duration":0.000929675,"size":10900,"status":200,"resp_headers":{"Server":["Caddy"],"Content-Encoding":["gzip"],"Content-Type":["text/html; charset=utf-8"],"Vary":["Accept-Encoding"]},"server":"1.2.3.4"}`
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		t.Error(err)
	}
	expectedServer := "1.2.3.4"
	if logitem.Server != expectedServer {
		t.Errorf("want (%v), get (%v)", expectedServer, logitem.Server)
	}
}

func TestMirrorNginxJSONFormat(t *testing.T) {
	logfmt := `{"timestamp": "%x.%^", "clientip": "%h", "serverip": "%S", "method": "%m", "url": "%U", "status": "%s", "size": "%b", "resp_time": "%T", "http_host": "%v", "referer": "%R", "user_agent": "%u"}`
	datefmt := goaccessfmt.Dates.Sec
	timefmt := goaccessfmt.Dates.Sec
	conf, err := goaccessfmt.SetupConfig(logfmt, datefmt, timefmt, location)
	if err != nil {
		t.Error(err)
	}
	logitem := goaccessfmt.GLogItem{}
	line := `{"timestamp":1678551332.293,"clientip":"123.45.67.8","serverip":"87.65.4.32","method":"GET","url":"/path/to/a/file","status":200,"size":3009,"resp_time":0.000,"http_host":"example.com","referer":"","user_agent":""}`
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		t.Error(err)
	}
	expectedLogitem := goaccessfmt.GLogItem{
		Host:      "123.45.67.8",
		Date:      "20230311",
		Time:      "16:15:32",
		Dt:        time.Date(2023, 3, 11, 16, 15, 32, 0, location),
		VHost:     "example.com",
		Method:    "GET",
		Req:       "/path/to/a/file",
		Status:    200,
		RespSize:  3009,
		Agent:     "",
		ServeTime: 0,
		Server:    "87.65.4.32",
	}
	if !reflect.DeepEqual(logitem, expectedLogitem) {
		t.Errorf("want (%v), get (%v)", expectedLogitem, logitem)
	}
}
