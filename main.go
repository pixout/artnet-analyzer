package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/boguslaw-wojcik/crc32a"
	"github.com/jsimonetti/go-artnet/packet"
	"github.com/jsimonetti/go-artnet/packet/code"

	"github.com/pixout/artnet-analyzer/pkg/stat"
)

type message struct {
	delay     time.Duration
	msg       []byte
	length    int
	remote_ip string
}

type messageQueue chan message

var mq messageQueue
var stat *artanalyzer.Stat
var output string

func (mq messageQueue) enqueue(m message) {
	mq <- m
}

func list_duration() {

	templ_format1 := "#\t%010d\tTimeCode\t%v\tOP\t%s\tDT\t%010v\tTM1\t%010v\tTM2\t%010v"
	templ_format2 := "\tUni\t%03d\t%03d\t%03d\tSeq\t%03d\tCRC32\t%08x"
	file, err := os.Create(output)
	fmt.Printf("Worker started waiting for the data\n")

	if err != nil {
		fmt.Printf("Error reading output file %s due to: %v ", output, err)
		return
	}

	for m := range mq {

		artp, err := packet.Unmarshal(m.msg)
		if err != nil {

			fmt.Printf("Error in ArtNet packet unmarshal due to: %v ", err)
			continue
		}

		if artp.GetOpCode() == code.OpOutput {

			dmx := packet.ArtDMXPacket{}
			data, err := artp.MarshalBinary()
			dmx.UnmarshalBinary(data)
			if err != nil {

				fmt.Printf("Error in ArtNet DMX unmarshal due to: %v ", err)
				continue
			}

			fmt.Fprintf(file, templ_format1+templ_format2+"\n",
				stat.Total_packets,
				time.Now().UnixNano(),
				"DMX",
				m.delay,
				stat.Total_ms,
				stat.Total_ns,
				dmx.Net,
				dmx.SubUni,
				dmx.Physical,
				dmx.Sequence,
				crc32a.Checksum(m.msg))

		} else {

			op := artp.GetOpCode()
			fmt.Fprintf(file, templ_format1+"\n",
				stat.Total_packets,
				time.Now().UnixNano(),
				op.String(),
				m.delay,
				stat.Total_ms,
				stat.Total_ns)

		}

		stat.Total_ms = stat.Total_ms + m.delay.Truncate(time.Millisecond)
		stat.Total_ns = stat.Total_ns + m.delay
		stat.Total_packets = stat.Total_packets + 1
	}
}

func init() {
	flag.StringVar(&output, "output", "output.tsv", "Output file for results")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	addr := net.UDPAddr{
		Port: 6454,
		IP:   nil,
	}

	flag.Parse()

	fmt.Printf("ArtNet Analyzer listening on the port: %v\n", addr.Port)
	fmt.Printf("Output file: %s\n", output)

	stat = artanalyzer.NewStat()
	mq = make(messageQueue, 100)
	go list_duration()

	go func() {
		flushTicker := time.NewTicker(time.Second)
		for range flushTicker.C {

			if stat.Total_packets > 0 {

				fmt.Printf("Statistics!\tTotal in (ms %010v, ns %010v) = (diff %010v), packets amount %010v, avg: %010v\n", stat.Total_ms, stat.Total_ns, stat.Total_ns-stat.Total_ms, stat.Total_packets, time.Duration(int(stat.Total_ns)/stat.Total_packets))
			}
		}
	}()

	ser, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Printf("Error listen port due to: %v\n", err)
		return
	}

	defer ser.Close()
	var prev time.Time
	p := make([]byte, 2048)

	for {
		nbytes, remoteaddr, err := ser.ReadFromUDP(p)

		if err != nil {
			fmt.Printf("Error Read UDP from addr %v due to: %v\n", remoteaddr, err)
			prev = time.Now()
			continue
		}

		if prev.IsZero() {
			prev = time.Now()

			mq.enqueue(message{time.Duration(0), p, nbytes, remoteaddr.String()})
		} else {

			cur := time.Now()
			mq.enqueue(message{cur.Sub(prev), p, nbytes, remoteaddr.String()})
		}

		prev = time.Now()
	}
}
