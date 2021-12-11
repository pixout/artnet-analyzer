package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
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
var filterOnlyDMX bool
var port int
var sourceIP string
var bufferPool sync.Pool

func (mq messageQueue) enqueue(m message) {
	mq <- m
}

func list_duration() {

	labels := "Frame Num #\tTime Code\tArtNet Operator\tDelay\tTotal time in ms\tTotal time in ns\tRemote Addr\tArtNet Universe\tArtNet Sequence\tCRC32A\n"
	templ_format1 := "%010d\t%v\t%s\t%010v\t%010v\t%010v\t%s"
	templ_format2 := "\tN%03d S%03d P%03d\t%03d\t%08x"
	file, err := os.Create(output)
	fmt.Printf("Worker started waiting for the data\n")

	if err != nil {
		fmt.Printf("Error reading output file %s due to: %v ", output, err)
		return
	}

	fmt.Fprintf(file, labels)

	for m := range mq {

		artp, err := packet.Unmarshal(m.msg)
		if err != nil {

			fmt.Printf("Error in ArtNet packet unmarshal due to: %v ", err)
			continue
		}

		if stat.Total_packets == 0 {
			m.delay = time.Duration(0) // for first packet delay is always 0
		}

		ignorePacket := false
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
				m.remote_ip,
				dmx.Net,
				dmx.SubUni,
				dmx.Physical,
				dmx.Sequence,
				crc32a.Checksum(m.msg[:m.length]))

		} else if !filterOnlyDMX {

			op := artp.GetOpCode()
			fmt.Fprintf(file, templ_format1+"\n",
				stat.Total_packets,
				time.Now().UnixNano(),
				op.String(),
				m.delay,
				stat.Total_ms,
				stat.Total_ns,
				m.remote_ip)

		} else {
			ignorePacket = true
		}

		if !ignorePacket {

			stat.Total_ms = stat.Total_ms + m.delay.Truncate(time.Millisecond)
			stat.Total_ns = stat.Total_ns + m.delay
			stat.Total_packets = stat.Total_packets + 1
		}

		bufferPool.Put(m.msg)
	}
}

func init() {
	flag.StringVar(&output, "output", "output.tsv", "Output file for results")
	flag.BoolVar(&filterOnlyDMX, "filter-only-artdmx", false, "Ignore all frames except ArtDMX")
	flag.IntVar(&port, "port", 6454, "ArtNet Port")
	flag.StringVar(&sourceIP, "listen-from-ip", "", "Listen from IP. (default from all)")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(sourceIP),
	}

	bufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, 530) },
	}

	flag.Parse()

	fmt.Printf("ArtNet frames Analyzer listening on the IP and port: %s:%v\n", sourceIP, addr.Port)
	fmt.Printf("Output file: %s\n", output)

	if filterOnlyDMX {
		fmt.Printf("Filtering ON. Ignore all packets except ArtDmx\n")
	}

	stat = artanalyzer.NewStat()
	mq = make(messageQueue, 1000000)
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

	ser.SetReadBuffer(10 * 1024)

	defer ser.Close()
	var prev time.Time

	for {
		p := bufferPool.Get().([]byte)
		nbytes, remoteaddr, err := ser.ReadFromUDP(p)

		if err != nil {
			fmt.Printf("Error Read UDP from addr %v due to: %v\n", remoteaddr, err)
			prev = time.Now()
			continue
		}

		cur := time.Now()
		mq.enqueue(message{cur.Sub(prev), p, nbytes, remoteaddr.String()})
		prev = time.Now()
	}
}
