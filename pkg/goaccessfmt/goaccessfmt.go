package goaccessfmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/itchyny/timefmt-go"
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

var httpMethods = []string{
	"OPTIONS",
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"TRACE",
	"CONNECT",
	"PATCH",
	"SEARCH",
	/* WebDav */
	"PROPFIND",
	"PROPPATCH",
	"MKCOL",
	"COPY",
	"MOVE",
	"LOCK",
	"UNLOCK",
	"VERSION-CONTROL",
	"REPORT",
	"CHECKOUT",
	"CHECKIN",
	"UNCHECKOUT",
	"MKWORKSPACE",
	"UPDATE",
	"LABEL",
	"MERGE",
	"BASELINE-CONTROL",
	"MKACTIVITY",
	"ORDERPATCH",
}

func extractMethod(token []byte) []byte {
	for _, method := range httpMethods {
		if strings.HasPrefix(string(bytes.ToUpper(token)), method) {
			return []byte(method)
		}
	}
	return nil
}

var httpProtocols = []string{
	"HTTP/1.0",
	"HTTP/1.1",
	"HTTP/2",
	"HTTP/3",
}

func extractProtocol(token []byte) []byte {
	for _, protocol := range httpProtocols {
		if strings.HasPrefix(string(bytes.ToUpper(token)), protocol) {
			return []byte(protocol)
		}
	}
	return nil
}

type GLogItem struct {
	Agent       string
	Date        string
	Host        string
	Method      string
	Protocol    string
	Qstr        string
	Ref         string
	Req         string
	Status      int
	Time        string
	VHost       string
	Userid      string
	CacheStatus string

	RespSize  uint64
	ServeTime uint64

	// UMS
	MimeType  string
	TLSType   string
	TLSCypher string

	Dt time.Time
}

const (
	ERR_SPEC_TOKN_NUL = 0x1
	ERR_SPEC_TOKN_INV = 0x2
	ERR_SPEC_SFMT_MIS = 0x3
	ERR_SPEC_LINE_INV = 0x4
)

func parseSpecErr(code int, spec byte, tkn []byte) error {
	tknStr := "-"
	if len(tkn) > 0 {
		tknStr = string(tkn)
	}

	switch code {
	case ERR_SPEC_TOKN_NUL:
		return fmt.Errorf("token for '%%%c' specifier is NULL", spec)
	case ERR_SPEC_TOKN_INV:
		return fmt.Errorf("token '%s' doesn't match specifier '%%%c'", tknStr, spec)
	case ERR_SPEC_SFMT_MIS:
		return fmt.Errorf("missing braces '%s' and ignore chars for specifier '%%%c'", tknStr, spec)
	case ERR_SPEC_LINE_INV:
		return errors.New("incompatible format due to early parsed line ending '\\0'")
	default:
		return fmt.Errorf("unknown error code: %d", code)
	}
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
	Timezone              time.Location
	DoubleDecodeEnabled   bool
	AppendMethod          bool
	AppendProtocol        bool
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
		return callback(prefix, strconv.FormatFloat(value, 'f', -1, 64))
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

func SetupConfig(logfmt string, datefmt string, timefmt string, timezone *time.Location) (Config, error) {
	var conf Config
	conf.IsJSON = isJSONLogFormat(logfmt)
	conf.LogFormat = unescapeStr(logfmt)
	conf.DateFormat = unescapeStr(datefmt)
	conf.TimeFormat = unescapeStr(timefmt)
	conf.Timezone = *timezone
	containsSpecifier(&conf)

	if conf.IsJSON {
		conf.jsonMap = make(map[string]string)
		err := parseJSONString(conf.LogFormat, func(key, value string) error {
			conf.jsonMap[key] = value
			return nil
		})
		if err != nil {
			return Config{}, err
		}
	}

	if setDateNumFormat(&conf) {
		setSpecDateTimeNumFormat(&conf)
		setSpecDateTimeFormat(&conf)
	}
	return conf, nil
}

func GetFmtFromPreset(preset string) (string, string, string, error) {
	preset = strings.ToUpper(preset)
	var logfmt string
	var datefmt string
	var timefmt string
	switch preset {
	case "CLOUDSTORAGE":
		datefmt = dates.Usec
		timefmt = times.Usec
	case "SQUID":
		fallthrough
	case "CADDY":
		datefmt = dates.Sec
		timefmt = times.Sec
	case "AWSELB":
		fallthrough
	case "AWSALB":
		fallthrough
	case "CLOUDFRONT":
		fallthrough
	case "W3C":
		datefmt = dates.W3C
		timefmt = times.Fmt24
	case "COMMON":
		fallthrough
	case "VCOMMON":
		fallthrough
	case "COMBINED":
		fallthrough
	case "VCOMBINED":
		fallthrough
	case "AWSS3":
		fallthrough
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
	if line == "" {
		return errors.New("empty line")
	}
	perc := 0
	tilde := 0
	lineBytesMut := []byte(line)
	fmtBytesMut := []byte(fmt)
	for i, r := range []byte(fmt) {
		if r == '%' {
			perc++
			continue
		}
		if r == '~' && perc == 0 {
			tilde++
			continue
		}
		if len(lineBytesMut) == 0 {
			return parseSpecErr(ERR_SPEC_LINE_INV, '-', nil)
		}
		if lineBytesMut[0] == '\n' {
			return nil
		}
		if tilde > 0 && r != 0 {
			if len(lineBytesMut) == 0 {
				return nil
			}
			fmtBytesMut = []byte(fmt)[i:]
			if err := specialSpecifier(logitem, &lineBytesMut, &fmtBytesMut); err != nil {
				return err
			}
			tilde = 0
		} else if perc > 0 && r != 0 {
			if len(lineBytesMut) == 0 {
				return nil
			}
			fmtBytesMut = []byte(fmt)[i:]
			end := getDelim(fmtBytesMut)
			if err := parseSpecifier(conf, logitem, &lineBytesMut, fmtBytesMut, end); err != nil {
				return err
			}
			perc = 0
		} else if perc > 0 && r == ' ' {
			return errors.New("space after %")
		} else {
			lineBytesMut = lineBytesMut[1:]
		}
	}
	return nil
}

func getDelim(p []byte) byte {
	// done, nothing to do
	if len(p) < 2 {
		return 0
	}

	// add the first delim
	return p[1]
}

// extractBraces parses the special host specifier and extracts the characters
// that need to be rejected when attempting to parse the XFF field.
// If unable to find both curly braces (boundaries), it returns an empty string and an error.
// On success, it returns the extracted reject set.
func extractBraces(p *[]byte) ([]byte, error) {
	s := *p
	var b1, b2 int
	esc := false

	// Iterate over the log format
	for i, c := range s {
		if c == '\\' {
			esc = true
		} else if c == '{' && !esc {
			b1 = i
		} else if c == '}' && !esc {
			b2 = i
			break
		} else {
			esc = false
		}
	}

	if b1 == 0 || b2 == 0 {
		return nil, errors.New("unable to find both curly braces")
	}

	len := b2 - (b1 + 1)
	if len <= 0 {
		return nil, errors.New("invalid brace content")
	}

	// Found braces, extract 'reject' character set
	ret := s[b1+1 : b2]
	*p = s[b2+1:]

	return ret, nil
}

func specialSpecifier(logitem *GLogItem, line *[]byte, format *[]byte) error {
	if (*format)[0] != 'h' {
		return nil
	}
	// find_xff_host() todo
	// For example, "~h{, }" is used in order to parse "11.25.11.53, 17.68.33.17" field
	skips, err := extractBraces(format)
	if err != nil {
		return err
	}
	fmt.Println(skips)
	todo()
	return nil
}

func handleDefaultCaseToken(str *[]byte, p []byte) error {
	var targetChar byte
	if len(p) < 2 {
		targetChar = 0
	} else {
		targetChar = p[1]
	}
	index := bytes.IndexByte(*str, targetChar)

	if index != -1 {
		*str = (*str)[index:]
	}

	return nil
}

func parsedString(pch []byte, str *[]byte, i int, movePtr bool) []byte {
	result := pch[:i]
	if movePtr {
		*str = pch[i:]
	}
	return bytes.Trim(result, " ")
}

func parseString(str *[]byte, delims []byte, cnt int) []byte {
	idx := 0
	pch := *str
	var end byte

	if len(delims) > 0 && delims[0] != 0 {
		if p := bytes.IndexAny(pch, string(delims)); p == -1 {
			return nil
		} else {
			end = pch[p]
		}
	}

	if end != 0 {
		for i, ch := range pch {
			if ch == end {
				idx++
			}
			if (ch == end && cnt == idx) || ch == 0 {
				return parsedString(pch, str, i, true)
			}
			// if ch == '\\' && i+1 < len(pch) {
			// 	i++
			// }
		}
	} else {
		return parsedString(pch, str, len(pch), true)
	}

	return nil
}

// CountMatches counts the number of matches of character c in the string s1.
//
// If the character is not found, 0 is returned.
// On success, the number of characters found is returned.
func countMatches(s1 []byte, c byte) int {
	n := 0
	for _, char := range s1 {
		if char == c {
			n++
		}
	}
	return n
}

// FindAlphaCount moves forward through the log byte slice until a non-space
// character is found and returns the count of spaces encountered.
func findAlphaCount(str []byte) int {
	cnt := 0
	for _, b := range str {
		if b == ' ' {
			cnt++
		} else {
			break
		}
	}
	return cnt
}

const (
	SECS = 1000000
	MILS = 1000
)

func str2time(str, fmt []byte) (*time.Time, error) {
	if len(str) == 0 || len(fmt) == 0 {
		return nil, errors.New("empty time string/format")
	}
	us := bytes.Equal(fmt, []byte("%f"))
	ms := bytes.Equal(fmt, []byte("%*"))
	if us || ms {
		ts, err := strconv.ParseUint(string(str), 10, 64)
		if err != nil {
			return nil, err
		}
		var seconds int64
		if us {
			seconds = int64(ts / SECS)
		} else if ms {
			seconds = int64(ts / MILS)
		} else {
			seconds = int64(ts)
		}
		t := time.Unix(seconds, 0)

		return &t, nil
	}

	t, err := timefmt.Parse(string(str), string(fmt))
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func setDate(logitem *GLogItem, t *time.Time) {
	logitem.Dt = logitem.Dt.AddDate(t.Year()-logitem.Dt.Year(), int(t.Month())-int(logitem.Dt.Month()), t.Day()-logitem.Dt.Day())
}

func setTime(logitem *GLogItem, t *time.Time) {
	logitem.Dt = time.Date(logitem.Dt.Year(), logitem.Dt.Month(), logitem.Dt.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), logitem.Dt.Location())
}

func parseReq(conf Config, line []byte, method, protocol *string) []byte {
	var req, request, dreq []byte
	var meth, proto []byte

	meth = extractMethod(line)

	// couldn't find a method, so use the whole request line
	if meth == nil {
		request = line
	} else {
		// method found, attempt to parse request
		req = line[len(meth):]
		ptr := bytes.LastIndexByte(req, ' ')
		if ptr != -1 {
			proto = extractProtocol(req[ptr+1:])
		}
		if ptr == -1 || proto == nil {
			return []byte("-")
		}

		req = bytes.TrimSpace(req)
		if len(req) == 0 {
			return []byte("-")
		}

		request = req[:bytes.LastIndexByte(req, ' ')]

		if conf.AppendMethod {
			*method = string(bytes.ToUpper(meth))
		}

		if conf.AppendProtocol {
			*protocol = string(bytes.ToUpper(proto))
		}
	}

	dreq = decodeURL(conf, request)
	if dreq == nil {
		return request
	}

	return dreq
}

// decodeURL is the entry point to decode the given URL-encoded string.
//
// On success, the decoded trimmed string is returned as a []byte.
func decodeURL(conf Config, s []byte) []byte {
	if len(s) == 0 {
		return nil
	}

	// First decoding
	decoded, err := url.QueryUnescape(string(s))
	if err != nil {
		return nil
	}

	// Double decoding if configured
	if conf.DoubleDecodeEnabled {
		decoded, err = url.QueryUnescape(decoded)
		if err != nil {
			return nil
		}
	}

	// Strip newlines
	decoded = strings.ReplaceAll(decoded, "\n", "")
	decoded = strings.ReplaceAll(decoded, "\r", "")

	// Trim spaces
	decoded = strings.TrimSpace(decoded)

	return []byte(decoded)
}

func parseSpecifier(conf Config, logitem *GLogItem, line *[]byte, specifier []byte, end byte) error {
	p := specifier[0]
	// fmt.Println(string(p), "|", string(*line), "|", string(end), "|")
	switch p {
	case 'd':
		if logitem.Date != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		// Take "Dec  2" and "Nov 22" cases into consideration
		fmtspcs := countMatches([]byte(conf.DateFormat), ' ')
		pch := bytes.IndexByte(*line, ' ')
		dspc := 0
		if fmtspcs > 0 && pch != -1 {
			dspc = findAlphaCount((*line)[pch:])
		}
		tkn := parseString(line, []byte{end}, max(dspc, fmtspcs)+1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		tm, err := str2time(tkn, []byte(conf.DateFormat))
		if err != nil {
			return err
		}
		date := timefmt.Format(*tm, conf.DateNumFormat)
		logitem.Date = date
		_, err = strconv.Atoi(date)
		if err != nil {
			return err
		}
		setDate(logitem, tm)
	case 't':
		if logitem.Time != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		tm, err := str2time(tkn, []byte(conf.TimeFormat))
		if err != nil {
			return err
		}
		time := timefmt.Format(*tm, "%H:%M:%S")
		logitem.Time = time
		setTime(logitem, tm)
	case 'x':
		if logitem.Time != "" && logitem.Date != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		tm, err := str2time(tkn, []byte(conf.TimeFormat))
		if err != nil {
			return err
		}
		date := timefmt.Format(*tm, conf.DateNumFormat)
		time := timefmt.Format(*tm, "%H:%M:%S")
		logitem.Date = date
		logitem.Time = time
		_, err = strconv.Atoi(date)
		if err != nil {
			return err
		}
		setDate(logitem, tm)
		setTime(logitem, tm)
	case 'v':
		if logitem.VHost != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		logitem.VHost = string(tkn)
	case 'e':
		if logitem.Userid != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		logitem.Userid = string(tkn)
	case 'C':
		if logitem.CacheStatus != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		switch strings.ToUpper(string(tkn)) {
		case "MISS", "BYPASS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED", "HIT":
			logitem.CacheStatus = string(tkn)
		}
	case 'h':
		if logitem.Host != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		if (*line)[0] == '[' && len(*line) >= 2 {
			end = ']'
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		logitem.Host = string(tkn)
	case 'm':
		if logitem.Method != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		meth := extractMethod(tkn)
		if meth == nil {
			return parseSpecErr(ERR_SPEC_TOKN_INV, p, tkn)
		}
		logitem.Method = string(meth)
	case 'U':
		/* request not including method or protocol */
		if logitem.Req != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		req := decodeURL(conf, tkn)
		if req == nil {
			return parseSpecErr(ERR_SPEC_TOKN_INV, p, tkn)
		}
		logitem.Req = string(req)
	case 'q':
		if logitem.Qstr != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return nil
		}
		qstr := decodeURL(conf, tkn)
		if qstr == nil {
			return parseSpecErr(ERR_SPEC_TOKN_INV, p, tkn)
		}
		logitem.Qstr = string(qstr)
	case 'H':
		if logitem.Protocol != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		proto := extractProtocol(tkn)
		if proto == nil {
			return parseSpecErr(ERR_SPEC_TOKN_INV, p, tkn)
		}
		logitem.Protocol = string(proto)
	case 'r':
		/* request, including method + protocol */
		if logitem.Req != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		req := parseReq(conf, tkn, &logitem.Method, &logitem.Protocol)
		logitem.Req = string(req)
	case 's':
		if logitem.Status >= 0 {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		status, err := strconv.ParseInt(string(tkn), 10, 32)
		if err != nil {
			return err
		}
		logitem.Status = int(status)
	case 'b':
		if logitem.RespSize > 0 {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		bandw, err := strconv.ParseUint(string(tkn), 10, 64)
		if err != nil {
			bandw = 0
		}
		logitem.RespSize = bandw
	case 'R':
		if logitem.Ref != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			tkn = []byte("-")
		}
		logitem.Ref = string(tkn)
	case 'u':
		if logitem.Agent != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn != nil {
			tkn = decodeURL(conf, tkn)
		} else {
			tkn = []byte("-")
		}
		logitem.Agent = string(tkn)
	case 'L':
		if logitem.ServeTime > 0 {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		serveSecs, err := strconv.ParseUint(string(tkn), 10, 64)
		if err != nil {
			serveSecs = 0
		}
		logitem.ServeTime = serveSecs * 1000
	case 'T':
		if logitem.ServeTime > 0 {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		var serveSecs float64
		var serveSecsUll uint64
		var err error
		if bytes.IndexByte(tkn, '.') != -1 {
			serveSecs, err = strconv.ParseFloat(string(tkn), 64)
		} else {
			serveSecsUll, err = strconv.ParseUint(string(tkn), 10, 64)
			serveSecs = float64(serveSecsUll)
		}
		if err != nil {
			serveSecs = 0
		}
		logitem.ServeTime = uint64(serveSecs * 1000000)
	case 'D':
		if logitem.ServeTime > 0 {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		serveTime, err := strconv.ParseUint(string(tkn), 10, 64)
		if err != nil {
			serveTime = 0
		}
		logitem.ServeTime = serveTime
	case 'n':
		if logitem.ServeTime > 0 {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		serveTime, err := strconv.ParseUint(string(tkn), 10, 64)
		if err != nil {
			serveTime = 0
		}
		logitem.ServeTime = serveTime / 1000
	case 'k':
		if logitem.TLSCypher != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		logitem.TLSCypher = string(tkn)
	case 'K':
		if logitem.TLSType != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		logitem.TLSType = string(tkn)
	case 'M':
		if logitem.MimeType != "" {
			return handleDefaultCaseToken(line, specifier)
		}
		tkn := parseString(line, []byte{end}, 1)
		if tkn == nil {
			return parseSpecErr(ERR_SPEC_TOKN_NUL, p, tkn)
		}
		logitem.MimeType = string(tkn)
	case '~':
		s := *line
		for i, r := range s {
			if r != ' ' {
				*line = s[i:]
				break
			}
		}
	default:
		return handleDefaultCaseToken(line, specifier)
	}
	return nil
}

func ParseLine(conf Config, line string, logitem *GLogItem) error {
	if !validLine(line) {
		return errors.New("invalid line")
	}
	// init logitem
	logitem.Status = -1
	logitem.Dt = logitem.Dt.In(&conf.Timezone)

	var err error
	if conf.IsJSON {
		err = parseJSONFormat(conf, line, logitem)
	} else {
		err = parseFormat(conf, line, logitem, conf.LogFormat)
	}

	return err
}

func PrintLog(logitem *GLogItem) {
	fmt.Println("Host", logitem.Host)
	fmt.Println("Date", logitem.Date)
	fmt.Println("Time", logitem.Time)
	fmt.Println("time.Time", logitem.Dt)
	fmt.Println("VHost", logitem.VHost)
	fmt.Println("Userid", logitem.Userid)
	fmt.Println("CacheStatus", logitem.CacheStatus)
	fmt.Println("Method", logitem.Method)
	fmt.Println("Req", logitem.Req)
	fmt.Println("Qstr", logitem.Qstr)
	fmt.Println("Protocol", logitem.Protocol)
	fmt.Println("Status", logitem.Status)
	fmt.Println("RespSize", logitem.RespSize)
	fmt.Println("Ref", logitem.Ref)
	fmt.Println("Agent", logitem.Agent)
	fmt.Println("ServeTime", logitem.ServeTime)
	fmt.Println("TLSCypher", logitem.TLSCypher)
	fmt.Println("TLSType", logitem.TLSType)
	fmt.Println("MimeType", logitem.MimeType)
}
