package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
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
var universes int

func (mq messageQueue) enqueue(m message) {
	mq <- m
}

func list_duration() {

	labels := "Frame Num #\tTime Code\tArtNet Operator\tDelay (ns)\tFPU time (ns)\tTotal time (ns)\tRemote Addr\tArtNet Universe\tSeq\tCRC32A\n"
	templ_format1 := "%010d %03d\t%v\t%s\t%010v\t%010v\t%010v\t%s"
	templ_format2 := "\tN%03d S%03d P%03d\t%03d\t%08x"
	file, err := os.Create(output)
	fmt.Printf("Worker started waiting for the data\n")

	if err != nil {
		fmt.Printf("Error reading output file %s due to: %v ", output, err)
		return
	}

	fmt.Fprintf(file, labels)
	dmx_frames_cnt := 0

	if universes > 0 {
		stat.ArtDmx_frames = 1
	}

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

			if universes > 0 && dmx_frames_cnt >= universes {
				dmx_frames_cnt = 0
				stat.FPU = m.delay
				fmt.Fprintf(file, "-%d-\n", stat.ArtDmx_frames)
				stat.ArtDmx_frames = stat.ArtDmx_frames + 1
			} else if universes > 0 {
				stat.FPU = stat.FPU + m.delay
			}

			dmx := packet.ArtDMXPacket{}
			data, err := artp.MarshalBinary()
			dmx.UnmarshalBinary(data)
			if err != nil {

				fmt.Printf("Error in ArtNet DMX unmarshal due to: %v ", err)
				continue
			}

			fmt.Fprintf(file, templ_format1+templ_format2+"\n",
				stat.Total_packets,
				dmx_frames_cnt,
				time.Now().UnixNano(),
				"DMX",
				m.delay,
				stat.FPU,
				stat.Total,
				m.remote_ip,
				dmx.Net,
				dmx.SubUni,
				dmx.Physical,
				dmx.Sequence,
				crc32a.Checksum(m.msg[:m.length]))

			if universes > 0 {
				dmx_frames_cnt = dmx_frames_cnt + 1
			}

		} else if !filterOnlyDMX {

			op := artp.GetOpCode()
			fmt.Fprintf(file, templ_format1+"\n",
				stat.Total_packets,
				0,
				time.Now().UnixNano(),
				op.String(),
				m.delay,
				0,
				stat.Total,
				m.remote_ip)

		} else {
			ignorePacket = true
		}

		if !ignorePacket {

			stat.Total = stat.Total + m.delay
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
	flag.IntVar(&universes, "universes", 0, "Frames Per Universes. How many universes are used?")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(sourceIP),
	}

	bufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, 1024) },
	}

	flag.Parse()
	if !flag.Parsed() {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("ArtNet frames Analyzer listening on the IP and port: %s:%v\n", sourceIP, addr.Port)
	fmt.Printf("Output file: %s\n", output)

	if filterOnlyDMX {
		fmt.Printf("Filtering ON. Ignore all packets except ArtDmx\n")
	}

	if universes > 0 {
		fmt.Printf("Specified universes. Report will be splitted by %d universes with FPU(Frames Per Universe) time\n", universes)
	}

	stat = artanalyzer.NewStat()
	mq = make(messageQueue, 1000000)
	var received_frames uint64
	received_frames = 0
	go list_duration()
	run_stat := false

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
		prev = cur
		atomic.AddUint64(&received_frames, 1)

		if !run_stat {
			go func() {
				flushTicker := time.NewTicker(time.Second)
				prev := atomic.LoadUint64(&received_frames)
				div := universes
				if div == 0 {
					div = 1
				}

				for range flushTicker.C {

					if stat.Total_packets > 0 {

						t := time.Now()
						rf := atomic.LoadUint64(&received_frames)
						fmt.Printf("Statistics\tTime: %10v\tFrames: %04v %04v, FPS: %04v\tAVG time per frame: %010v\n",
							t.Format(time.UnixDate),
							rf, rf-prev,
							float32(float32(rf-prev)/float32(div)),
							time.Duration(int(stat.Total)/stat.ArtDmx_frames))

						prev = rf
					}
				}
			}()
			run_stat = true
		}
	}
}
