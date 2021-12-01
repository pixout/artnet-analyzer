package main

import (
	"fmt"
	"net"
	"runtime"
	"time"
        "flag"

	"github.com/boguslaw-wojcik/crc32a"
	"github.com/jsimonetti/go-artnet/packet"
	"github.com/jsimonetti/go-artnet/packet/code"

	"./pkg/stat"
)

type message struct {
	delay     time.Duration
	msg       []byte
	length    int
	remote_ip string
}

type messageQueue chan message

var mq messageQueue
var stat artanalyzer.Stat

func (mq messageQueue) enqueue(m message) {
	mq <- m
}

func list_duration() {
	for m := range mq {

		stat.Total_ms = stat.Total_ms + m.delay.Truncate(time.Millisecond)
		stat.Total_ns = stat.Total_ns + m.delay
		stat.Total_packets = stat.Total_packets + 1

		artp, err := packet.Unmarshal(m.msg)
		if err != nil {

			fmt.Printf("ArtNet decode error %v ", err)
		} else {

			op := artp.GetOpCode()

			fmt.Printf("ArtNet: OpCode %s ", op.String())
		}

		if artp.GetOpCode() == code.OpOutput {

			dmx := packet.ArtDMXPacket{}
			data, err := artp.MarshalBinary()
			dmx.UnmarshalBinary(data)
			if err != nil {

				fmt.Printf("ArtNet: Uni erroor %v ", err)
			} else {

				fmt.Printf("ArtNet: Uni %d-%d-%d,%d ", dmx.Net, dmx.SubUni, dmx.Physical, dmx.Sequence)
			}
		}

		fmt.Printf("delay %v ", m.delay)
		fmt.Printf("CRC32: %08x, timecode %v\n", crc32a.Checksum(m.msg), time.Now().UnixNano())

		//            fmt.Printf("time: %v\n", m)
	}
}

func sendResponse(conn *net.UDPConn, addr *net.UDPAddr) {
	_, err := conn.WriteToUDP([]byte("From server: Hello I got your message "), addr)
	if err != nil {
		fmt.Printf("Couldn't send response %v", err)
	}
}

func init() {
	//	flag.BoolVar(&useMs, "ms", false, "Use miliseconds if true")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	p := make([]byte, 2048)
	addr := net.UDPAddr{
		Port: 6454,
		IP:   nil,
	}

	flag.Parse()

	stat := artanalyzer.NewStat()

	mq = make(messageQueue, 100)
	go list_duration()

	go func() {
		flushTicker := time.NewTicker(time.Second)
		for range flushTicker.C {

			if stat.Total_packets > 0 {

				fmt.Printf("total time: ms %v, ns %v  (diff %v), packets amount %v, avg: %v\n", stat.Total_ms, stat.Total_ns, stat.Total_ns-stat.Total_ms, stat.Total_packets, time.Duration(int(stat.Total_ns)/stat.Total_packets))
			}
		}
	}()

	fmt.Printf("Server listening on the port: %v\n", addr.Port)

	ser, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Printf("Some error %v\n", err)
		return
	}

	defer ser.Close()
	var prev time.Time

	for {
		nbytes, remoteaddr, err := ser.ReadFromUDP(p)

		if prev.IsZero() {
			prev = time.Now()

			mq.enqueue(message{time.Duration(0), p, nbytes, remoteaddr.String()})
		} else {

			cur := time.Now()
			mq.enqueue(message{cur.Sub(prev), p, nbytes, remoteaddr.String()})
		}

		prev = time.Now()

		//fmt.Printf("Read a message from: %s, %v, size: %d \n", remoteaddr, p[0:num], num)
		if err != nil {
			fmt.Printf("Some error: addr  %v, err %v, data: %v", remoteaddr, err, p)
			continue
		}
	}
}
