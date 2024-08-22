package goaccessfmt

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

func ParseConfigReader(r io.Reader) (Config, error) {
	scanner := bufio.NewScanner(r)

	timeFormat := ""
	dateFormat := ""
	logFormat := ""
	tz := ""
	doubleDecode := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "time-format ") {
			timeFormat = strings.TrimSpace(strings.TrimPrefix(line, "time-format "))
		} else if strings.HasPrefix(line, "date-format ") {
			dateFormat = strings.TrimSpace(strings.TrimPrefix(line, "date-format "))
		} else if strings.HasPrefix(line, "log-format") {
			logFormat = strings.TrimSpace(strings.TrimPrefix(line, "log-format "))
		} else if strings.HasPrefix(line, "tz ") {
			tz = strings.TrimSpace(strings.TrimPrefix(line, "tz "))
		} else if strings.HasPrefix(line, "double-decode ") {
			dd := strings.TrimSpace(strings.TrimPrefix(line, "double-decode "))
			if dd == "false" {
				doubleDecode = false
			} else if dd == "true" {
				doubleDecode = true
			} else {
				return Config{}, errors.New("double-decode value is not a boolean")
			}
		}
	}
	if logFormat == "" {
		return Config{}, errors.New("empty log-format")
	}
	l, d, t, err := GetFmtFromPreset(logFormat)
	if err == nil {
		timeFormat = t
		dateFormat = d
		logFormat = l
	} else {
		if timeFormat == "" {
			return Config{}, errors.New("empty time-format")
		}
		if dateFormat == "" {
			return Config{}, errors.New("empty date-format")
		}
	}
	var location *time.Location
	if tz == "" {
		location = time.Now().Location()
	} else {
		// try trim UTC prefix
		offsetStr := strings.TrimPrefix(tz, "UTC")
		offsetHours, err := strconv.Atoi(offsetStr)
		if err != nil {
			location, err = time.LoadLocation(tz)
			if err != nil {
				return Config{}, err
			}
		} else {
			location = time.FixedZone(tz, offsetHours*60*60)
		}
	}
	conf, err := SetupConfig(logFormat, dateFormat, timeFormat, location)
	if err != nil {
		return Config{}, err
	}
	conf.DoubleDecodeEnabled = doubleDecode
	return conf, nil
}
