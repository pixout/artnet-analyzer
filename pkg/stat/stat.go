package artanalyzer

import (
	"time"
)

type Stat struct {
	Total_packets int
	Total_ns      time.Duration
	Total_ms      time.Duration
}

func NewStat() *Stat {
	return &Stat{Total_packets: 0}
}
