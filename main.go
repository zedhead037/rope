package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

func handleSocks4(buf []byte, conn net.Conn) {
	destPort := binary.BigEndian.Uint16(buf[2:4])
	destIP := net.IPv4(buf[4], buf[5], buf[6], buf[7])
	destAddr := fmt.Sprintf("%s:%d", destIP.String(), destPort)
	log.Printf("[SOCKSv4] req %s from %s\n", destAddr, conn.RemoteAddr())

	target, err := net.Dial("tcp4", destAddr)
	if err != nil {
		conn.Write([]byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()

	conn.Write([]byte{0x00, 0x5A, 0, 0, 0, 0, 0, 0})

	go io.Copy(target, conn)
	io.Copy(conn, target)
}

func handleSocks5(buf []byte, conn net.Conn) {
	i := 1
	// ignore everything & use no auth.
	conn.Write([]byte{0x05, 0x00})
	_, err := conn.Read(buf)
	if err != nil {
		conn.Write([]byte{0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		conn.Close()
	}
	reqDstAddrType := buf[3]
	var reqDstAddr string
	var reqDstAddrBytes []byte
	switch reqDstAddrType {
	case 0x01:
		reqDstAddr = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		reqDstAddrBytes = buf[3:8]
		i = 8
	case 0x03:
		nameLen := buf[4]
		reqDstAddr = string(buf[5:5+nameLen])
		reqDstAddrBytes = buf[3:5+nameLen]
		i = 5+int(nameLen)
	case 0x04:
		reqDstAddr = net.IP{buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]}.String()
		reqDstAddrBytes = buf[3:20]
		i = 20
	}
	reqDstPort := (int(buf[i])<<8)|int(buf[i+1])

	var reqAddr string
	if reqDstAddrType == 0x04 {
		reqAddr = fmt.Sprintf("[%s]:%d", reqDstAddr, reqDstPort)
	} else {
		reqAddr = fmt.Sprintf("%s:%d", reqDstAddr, reqDstPort)
	}
	log.Printf("[SOCKSv5] req %s from %s\n", reqAddr, conn.RemoteAddr().String())
	target, err := net.Dial("tcp", reqAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00})
		conn.Write(reqDstAddrBytes)
		conn.Write([]byte{byte(reqDstPort>>8), byte(reqDstPort|0xff)})
		conn.Close()
		return
	} else {
		conn.Write([]byte{0x05, 0x00, 0x00})
		conn.Write(reqDstAddrBytes)
		conn.Write([]byte{byte(reqDstPort>>8), byte(reqDstPort|0xff)})
	}
	defer target.Close()
	go io.Copy(target, conn)
	io.Copy(conn, target)
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return
	}

	switch buf[0] {
	case 4: // socks 4
		if buf[1] != 0x01 { // not CONNECT
			return
		}
		handleSocks4(buf, conn)
	case 5: // socks
		handleSocks5(buf, conn)
	}

}

func main() {
	listener, err := net.Listen("tcp", ":1080")
	if err != nil {
		panic(err)
	}
	log.Println("Listening on port 1080")

	for {
		conn, err := listener.Accept()
		log.Printf("Accepted: %s\n", conn.RemoteAddr().String())
		if err != nil {
			continue
		}
		go handleClient(conn)
	}
}

