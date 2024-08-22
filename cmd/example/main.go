package main

import (
	"fmt"
	"time"

	"github.com/taoky/goaccessfmt/pkg/goaccessfmt"
)

func main() {
	logfmt, datefmt, timefmt, err := goaccessfmt.GetFmtFromPreset("combined")
	if err != nil {
		panic(err)
	}
	conf := goaccessfmt.SetupConfig(logfmt, datefmt, timefmt, time.FixedZone("UTC+8", 8*60*60))
	var logitem goaccessfmt.GLogItem

	line := `114.5.1.4 - - [11/Jun/2023:11:23:45 +0800] "GET /example/path/file.img HTTP/1.1" 429 568 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"`
	fmt.Println(line)
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		fmt.Println(err)
	} else {
		goaccessfmt.PrintLog(&logitem)
		fmt.Println()
	}

	logfmt, datefmt, timefmt, err = goaccessfmt.GetFmtFromPreset("caddy")
	if err != nil {
		panic(err)
	}
	conf = goaccessfmt.SetupConfig(logfmt, datefmt, timefmt, time.FixedZone("UTC+8", 8*60*60))
	logitem = goaccessfmt.GLogItem{}
	line = `{"level":"info","ts":1646861401.5241024,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"41342","client_ip":"127.0.0.1","proto":"HTTP/2.0","method":"GET","host":"localhost","uri":"/","headers":{"User-Agent":["curl/7.82.0"],"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"example.com"}},"bytes_read": 0,"user_id":"","duration":0.000929675,"size":10900,"status":200,"resp_headers":{"Server":["Caddy"],"Content-Encoding":["gzip"],"Content-Type":["text/html; charset=utf-8"],"Vary":["Accept-Encoding"]}}`
	fmt.Println(line)
	err = goaccessfmt.ParseLine(conf, line, &logitem)
	if err != nil {
		fmt.Println(err)
	} else {
		goaccessfmt.PrintLog(&logitem)
		fmt.Println()
	}
}
