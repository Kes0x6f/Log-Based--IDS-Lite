package parsetimestamp

import (
	"fmt"
	"time"
)

func ParseTimeStamp(ts string) (time.Time, error) {
	year := time.Now().Year()
	layout := "2006 Jan 2 15:04:05"
	return time.Parse(layout, fmt.Sprintf("%d %s", year, ts))
}
