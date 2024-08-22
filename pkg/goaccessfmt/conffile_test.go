package goaccessfmt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/taoky/goaccessfmt/pkg/goaccessfmt"
)

func TestBasicConffile(t *testing.T) {
	basicConfig := `log-format combined
tz UTC+8`
	r := strings.NewReader(basicConfig)
	c, err := goaccessfmt.ParseConfigReader(r)
	if err != nil {
		t.Error(err)
	}
	if c.LogFormat != goaccessfmt.Logs.Combined || c.DateFormat != goaccessfmt.Dates.Apache || c.TimeFormat != goaccessfmt.Times.Fmt24 {
		t.Error("conf does not match that of combined")
	}
	if c.DoubleDecodeEnabled != false {
		t.Error("double decode is enabled")
	}
	loc := c.Timezone
	now := time.Now()
	nowInLoc := now.In(&loc)
	_, offset := nowInLoc.Zone()
	if offset != 8*60*60 {
		t.Error("timezone is not UTC+8")
	}
}
