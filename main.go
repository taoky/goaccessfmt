package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

func todo() {
	panic("not implemented")
}

// GPreConfLog represents predefined log formats
type GPreConfLog struct {
	Combined     string
	VCombined    string
	Common       string
	VCommon      string
	W3C          string
	CloudFront   string
	CloudStorage string
	AWSELB       string
	Squid        string
	AWSS3        string
	Caddy        string
	AWSALB       string
	TraefikCLF   string
}

var logs = GPreConfLog{
	Combined:     `%h %^[%d:%t %^] "%r" %s %b "%R" "%u"`,
	VCombined:    `%v:%^ %h %^[%d:%t %^] "%r" %s %b "%R" "%u"`,
	Common:       `%h %^[%d:%t %^] "%r" %s %b`,
	VCommon:      `%v:%^ %h %^[%d:%t %^] "%r" %s %b`,
	W3C:          `%d %t %^ %m %U %q %^ %^ %h %u %R %s %^ %^ %L`,
	CloudFront:   `%d\t%t\t%^\t%b\t%h\t%m\t%v\t%U\t%s\t%R\t%u\t%q\t%^\t%C\t%^\t%^\t%^\t%^\t%T\t%^\t%K\t%k\t%^\t%H\t%^`,
	CloudStorage: `"%x","%h",%^,%^,"%m","%U","%s",%^,"%b","%D",%^,"%R","%u"`,
	AWSELB:       `%^ %dT%t.%^ %^ %h:%^ %^ %^ %T %^ %s %^ %^ %b "%r" "%u" %k %K %^ "%^" "%v"`,
	Squid:        `%^ %^ %^ %v %^: %x.%^ %~%L %h %^/%s %b %m %U`,
	AWSS3:        `%^ %v [%d:%t %^] %h %^"%r" %s %^ %b %^ %L %^ "%R" "%u"`,
	Caddy:        `{ "ts": "%x.%^", "request": { "client_ip": "%h", "proto":"%H", "method": "%m", "host": "%v", "uri": "%U", "headers": {"User-Agent": ["%u"], "Referer": ["%R"] }, "tls": { "cipher_suite":"%k", "proto": "%K" } }, "duration": "%T", "size": "%b","status": "%s", "resp_headers": { "Content-Type": ["%M"] } }`,
	AWSALB:       `%^ %dT%t.%^ %v %h:%^ %^ %^ %T %^ %s %^ %^ %b "%r" "%u" %k %K %^`,
	TraefikCLF:   `%h - %e [%d:%t %^] "%r" %s %b "%R" "%u" %^ "%v" "%U" %Lms`,
}

// GPreConfTime represents predefined log time formats
type GPreConfTime struct {
	Fmt24 string
	Usec  string
	Sec   string
}

// GPreConfDate represents predefined log date formats
type GPreConfDate struct {
	Apache string
	W3C    string
	Usec   string
	Sec    string
}

var times = GPreConfTime{
	Fmt24: "%H:%M:%S",
	Usec:  "%f", // Cloud Storage (usec)
	Sec:   "%s", // Squid (sec)
}

var dates = GPreConfDate{
	Apache: "%d/%b/%Y", // Apache
	W3C:    "%Y-%m-%d", // W3C
	Usec:   "%f",       // Cloud Storage (usec)
	Sec:    "%s",       // Squid (sec)
}

type GLogItem struct {
	agent       string
	date        string
	host        string
	keyphrase   string
	method      string
	protocol    string
	qstr        string
	ref         string
	req         string
	status      int
	time        string
	vhost       string
	userid      string
	cacheStatus string

	site string

	respSize   int
	serve_time int

	numdate int

	// UMS
	mimeType      string
	tlsType       string
	tlsCypher     string
	tlsTypeCypher string

	dt time.Time
}

// isJSONLogFormat determines if we have a valid JSON format
func isJSONLogFormat(fmt string) bool {
	decoder := json.NewDecoder(strings.NewReader(fmt))
	decoder.UseNumber() // This makes the decoder stricter, similar to json_set_streaming(&json, false)

	// Parse the JSON
	var j interface{}
	err := decoder.Decode(&j)
	if err != nil {
		return false
	}

	// Check if there's any trailing data after the JSON
	_, err = decoder.Token()
	return err == io.EOF
}

// unescapeStr gets an unescaped string
//
// On error, an empty string is returned.
// On success, the unescaped string is returned.
func unescapeStr(src string) string {
	if src == "" {
		return ""
	}

	var dest strings.Builder
	dest.Grow(len(src))

	for i := 0; i < len(src); i++ {
		if src[i] == '\\' {
			i++
			if i >= len(src) {
				// warning...
				break
			}
			switch src[i] {
			case 'n':
				dest.WriteByte('\n')
			case 'r':
				dest.WriteByte('\r')
			case 't':
				dest.WriteByte('\t')
			default:
				dest.WriteByte(src[i])
			}
		} else {
			dest.WriteByte(src[i])
		}
	}

	return dest.String()
}

type Config struct {
	LogFormat             string
	DateFormat            string
	TimeFormat            string
	DateNumFormat         string
	SpecDateTimeNumFormat string
	SpecDateTimeFormat    string
	ServeUsecs            bool
	Bandwidth             bool
	IsJSON                bool
	jsonMap               map[string]string
	DateSpecHr            int // 1: hr, 2: min
}

func containsSpecifier(conf *Config) {
	// Reset flags
	conf.ServeUsecs = false
	conf.Bandwidth = false

	if conf.LogFormat == "" {
		return
	}

	if strings.Contains(conf.LogFormat, "%b") {
		conf.Bandwidth = true
	}
	if strings.Contains(conf.LogFormat, "%D") ||
		strings.Contains(conf.LogFormat, "%T") ||
		strings.Contains(conf.LogFormat, "%L") {
		conf.ServeUsecs = true
	}
}

// cleanDateTimeFormat iterates over the given format and cleans unwanted chars,
// keeping all date/time specifiers such as %b%Y%d%M%S.
//
// On error, an empty string is returned.
// On success, a clean format containing only date/time specifiers is returned.
func cleanDateTimeFormat(format string) string {
	if format == "" {
		return ""
	}

	var builder strings.Builder
	special := false

	for _, ch := range format {
		if ch == '%' || special {
			builder.WriteRune(ch)
			special = !special
		}
	}

	return builder.String()
}

// hasTimestamp determines if the given date format is a timestamp.
//
// If it's not a timestamp, false is returned.
// If it is a timestamp, true is returned.
func hasTimestamp(fmt string) bool {
	return fmt == "%s" || fmt == "%f"
}

func setFormatDate(conf Config) string {
	if hasTimestamp(conf.DateFormat) {
		return "%Y%m%d"
	}
	return cleanDateTimeFormat(conf.DateFormat)
}

func setFormatTime(conf Config) string {
	if hasTimestamp(conf.DateFormat) || conf.TimeFormat == "%T" {
		return "%H%M%S"
	}
	return cleanDateTimeFormat(conf.TimeFormat)
}

// isDateAbbreviated determines if the given specifier character is an abbreviated type of date.
//
// If it is, true is returned, otherwise, false is returned.
func isDateAbbreviated(fdate string) bool {
	return strings.ContainsAny(fdate, "cDF")
}

const MinDateNumFmtLen = 7

// setDateNumFormat normalizes the date format from the user-provided format to Ymd
// so it can be properly sorted afterwards.
// Returns:
//   - true if the format was successfully set (even if empty).
//   - false if there was an error or the format couldn't be determined.
func setDateNumFormat(conf *Config) bool {
	fdate := setFormatDate(*conf)
	if fdate == "" {
		return false
	}

	if isDateAbbreviated(fdate) {
		conf.DateNumFormat = "%Y%m%d"
		return true
	}

	flen := len(fdate) + 1
	if flen < MinDateNumFmtLen {
		flen = MinDateNumFmtLen
	}

	var buf strings.Builder
	buf.Grow(flen)

	// always add a %Y
	buf.WriteString("%Y")
	if strings.ContainsAny(fdate, "hbmBf*") {
		buf.WriteString("%m")
	}
	if strings.ContainsAny(fdate, "def*") {
		buf.WriteString("%d")
	}

	conf.DateNumFormat = buf.String()

	return buf.Len() > 0
}

func setSpecDateTimeNumFormat(conf *Config) {
	df := conf.DateNumFormat
	tf := setFormatTime(*conf)

	if df == "" || tf == "" {
		return
	}

	var buf string

	switch {
	case conf.DateSpecHr == 1 && strings.Contains(tf, "H"):
		buf = df + "%H"
	case conf.DateSpecHr == 2 && strings.Contains(tf, "M"):
		buf = df + "%H%M"
	default:
		buf = df
	}

	conf.SpecDateTimeNumFormat = buf
}

func setSpecDateTimeFormat(conf *Config) {
	fmt := conf.SpecDateTimeNumFormat
	if fmt == "" {
		return
	}

	var buf strings.Builder
	buf.Grow(len(fmt) * 2) // Allocate enough capacity

	if strings.Contains(fmt, "d") {
		buf.WriteString("%d/")
	}
	if strings.Contains(fmt, "m") {
		buf.WriteString("%b/")
	}
	if strings.Contains(fmt, "Y") {
		buf.WriteString("%Y")
	}
	if strings.Contains(fmt, "H") {
		buf.WriteString(":%H")
	}
	if strings.Contains(fmt, "M") {
		buf.WriteString(":%M")
	}

	conf.SpecDateTimeFormat = buf.String()
}

// callback is the function type for the callback
type callback func(key, value string) error

// parseJSONString parses a JSON string and calls the callback function for each key-value pair
func parseJSONString(jsonStr string, callback callback) error {
	var data interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return err
	}

	return parseValue("", data, callback)
}

func parseValue(prefix string, v interface{}, callback callback) error {
	switch value := v.(type) {
	case map[string]interface{}:
		for k, v := range value {
			newPrefix := joinKey(prefix, k)
			if err := parseValue(newPrefix, v, callback); err != nil {
				return err
			}
		}
	case []interface{}:
		for i, v := range value {
			newPrefix := fmt.Sprintf("%s[%d]", prefix, i)
			if err := parseValue(newPrefix, v, callback); err != nil {
				return err
			}
		}
	case string:
		return callback(prefix, value)
	case float64:
		return callback(prefix, fmt.Sprintf("%v", value))
	case bool:
		return callback(prefix, fmt.Sprintf("%v", value))
	case nil:
		return callback(prefix, "null")
	default:
		return fmt.Errorf("unknown type: %T", v)
	}
	return nil
}

func joinKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func setupConfig(logfmt string, datefmt string, timefmt string) Config {
	var conf Config
	conf.IsJSON = isJSONLogFormat(logfmt)
	conf.LogFormat = unescapeStr(logfmt)
	conf.DateFormat = unescapeStr(datefmt)
	conf.TimeFormat = unescapeStr(timefmt)
	containsSpecifier(&conf)

	if conf.IsJSON {
		conf.jsonMap = make(map[string]string)
		parseJSONString(conf.LogFormat, func(key, value string) error {
			conf.jsonMap[key] = value
			return nil
		})
	}

	if setDateNumFormat(&conf) {
		setSpecDateTimeNumFormat(&conf)
		setSpecDateTimeFormat(&conf)
	}
	return conf
}

func getFmtFromPreset(preset string) (string, string, string, error) {
	preset = strings.ToUpper(preset)
	var logfmt string
	var datefmt string
	var timefmt string
	switch preset {
	case "CLOUDSTORAGE":
		datefmt = dates.Usec
		timefmt = times.Usec
	case "SQUID":
	case "CADDY":
		datefmt = dates.Sec
		timefmt = times.Sec
	case "AWSELB":
	case "AWSALB":
	case "CLOUDFRONT":
	case "W3C":
		datefmt = dates.W3C
		timefmt = times.Fmt24
	case "COMMON":
	case "VCOMMON":
	case "COMBINED":
	case "VCOMBINED":
	case "AWSS3":
	case "TRAEFIKCLF":
		datefmt = dates.Apache
		timefmt = times.Fmt24
	default:
		return "", "", "", errors.New("match failed")
	}
	switch preset {
	case "CLOUDSTORAGE":
		logfmt = logs.CloudFront
	case "SQUID":
		logfmt = logs.Squid
	case "CADDY":
		logfmt = logs.Caddy
	case "AWSELB":
		logfmt = logs.AWSELB
	case "AWSALB":
		logfmt = logs.AWSALB
	case "CLOUDFRONT":
		logfmt = logs.CloudFront
	case "W3C":
		logfmt = logs.W3C
	case "COMMON":
		logfmt = logs.Common
	case "VCOMMON":
		logfmt = logs.VCommon
	case "COMBINED":
		logfmt = logs.Combined
	case "VCOMBINED":
		logfmt = logs.VCombined
	case "AWSS3":
		logfmt = logs.AWSS3
	case "TRAEFIKCLF":
		logfmt = logs.TraefikCLF
	default:
		panic("unreachable")
	}
	return logfmt, datefmt, timefmt, nil
}

// validLine determines if the log string is valid and if it's not a comment.
//
// On error, or invalid, false is returned.
// On success, or valid line, true is returned.
func validLine(line string) bool {
	// invalid line
	if line == "" {
		return false
	}

	// ignore comments or empty lines
	if line[0] == '#' || line[0] == '\n' {
		return false
	}

	return true
}

func parseJSONFormat(conf Config, line string, logitem *GLogItem) error {
	return parseJSONString(line, func(key, value string) error {
		if len(value) == 0 || len(key) == 0 {
			return nil
		}
		spec, exists := conf.jsonMap[key]
		if !exists {
			return nil
		}
		return parseFormat(conf, value, logitem, spec)
	})
}

func parseFormat(conf Config, line string, logitem *GLogItem, fmt string) error {
	todo()
	return nil
}

func parseLine(conf Config, line string, logitem *GLogItem) error {
	if !validLine(line) {
		return errors.New("invalid line")
	}
	// init logitem
	logitem.status = -1

	var err error
	if conf.IsJSON {
		err = parseJSONFormat(conf, line, logitem)
	} else {
		err = parseFormat(conf, line, logitem, conf.LogFormat)
	}

	return err
}

func main() {
	logfmt, datefmt, timefmt, err := getFmtFromPreset("caddy")
	if err != nil {
		panic(err)
	}
	conf := setupConfig(logfmt, datefmt, timefmt)
	fmt.Println(conf.jsonMap)
	var logitem GLogItem

	line := `114.5.1.4 - - [11/Jun/2023:01:23:45 +0800] "GET /example/path/file.img HTTP/1.1" 429 568 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"`
	parseLine(conf, line, &logitem)
}
