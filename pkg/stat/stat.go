package artanalyzer

import (
	"time"
)

type Stat struct {
	Total_packets int
	ArtDmx_frames int
	Total         time.Duration
	FPU           time.Duration
}

func NewStat() *Stat {
	return &Stat{Total_packets: 0, ArtDmx_frames: 0, Total: time.Duration(0), FPU: time.Duration(0) }
}
