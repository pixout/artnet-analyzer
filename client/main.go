package main

import (
	"fmt"
	"math/rand"
	"net"
	"time"
)

func main() {

	rand.Seed(time.Now().UnixNano())
	buf := make([]byte, 512+30) //artnet packet
	for i := range buf {
		buf[i] = 255
	}

	laddr := net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 6454}
	raddr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6454}

	conn, err := net.DialUDP("udp", &laddr, &raddr)
	if err != nil {
		fmt.Printf("Some error2 %v", err)
		return
	}

	var rnd int32
	rnd = 1

	start := time.Now()
	for i := 0; i < 115200; i++ { //30fps, 64u, 60sec

		if i%1000 == 0 {
			rnd = rand.Int31n(10)
		}

		conn.Write(buf)
		time.Sleep(time.Duration(rnd) * time.Millisecond)
	}

	end := time.Now()
	fmt.Printf("time elapsed %v", end.Sub(start))

	conn.Close()
}
