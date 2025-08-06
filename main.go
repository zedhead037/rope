package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/zedhead037/mdconf"
)

var KEY_SOCKS_CLIENTMODE_ENABLE = []string{"socks", "clientMode", "enable"}
var KEY_SOCKS_CLIENTMODE_SERVERADDR = []string{"socks", "clientMode", "serverAddr"}
var KEY_SOCKS_CLIENTMODE_SERVERPORT = []string{"socks", "clientMode", "serverPort"}
var KEY_SOCKS_CLIENTMODE_USERNAME = []string{"socks", "clientMode", "username"}
var KEY_SOCKS_CLIENTMODE_PASSWORD = []string{"socks", "clientMode", "password"}
var KEY_SOCKS_V4_ENABLE = []string{"socks", "v4", "enable"}
var KEY_SOCKS_V4_BINDADDR = []string{"socks", "v4", "bindAddr"}
var KEY_SOCKS_V4_BINDPORT = []string{"socks", "v4", "bindPort"}
var KEY_SOCKS_V5_ENABLE = []string{"socks", "v5", "enable"}
var KEY_SOCKS_V5_BINDADDR = []string{"socks", "v5", "bindAddr"}
var KEY_SOCKS_V5_BINDPORT = []string{"socks", "v5", "bindPort"}

func initConfigAt(configPath string) *mdconf.MDConfSection {
	res := new(mdconf.MDConfSection)
	socks, _ := res.LocalAddSection("socks")
	v4, _ := socks.LocalAddSection("v4")
	v4.LocalSetKey("enable", "true")
	v4.LocalSetKey("bindAddr", "127.0.0.1")
	v4.LocalSetKey("bindPort", "1080")
	v5, _ := socks.LocalAddSection("v5")
	v5.LocalSetKey("enable", "true")
	v5.LocalSetKey("bindAddr", "127.0.0.1")
	v5.LocalSetKey("bindPort", "1080")
    clientMode, _ := socks.LocalAddSection("clientMode")
	clientMode.LocalSetKey("enable", "false")
	clientMode.LocalSetKey("serverAddr", "")
	clientMode.LocalSetKey("serverPort", "")
	clientMode.LocalSetKey("username", "")
	clientMode.LocalSetKey("password", "")
	os.WriteFile(configPath, []byte(res.ToString()), 0644)
	return res
}

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

func handleSocksClient(conn net.Conn) {
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

func handleSocksv4Only(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 9 { return }
	if buf[0] == 4 { handleSocks4(buf, conn) }
}

func handleSocksv5Only(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 3 { return }
	if buf[0] == 5 { handleSocks5(buf, conn) }
}

func isIPv6(s string) bool {
	return strings.Contains(s, ":")
}
func toFullAddr(host string, port string) string {
	if isIPv6(host) {
		return fmt.Sprintf("[%s]:%s", host, port)
	} else {
		return fmt.Sprintf("%s:%s", host, port)
	}
}

func main() {
	argparse := flag.NewFlagSet("rope", flag.ContinueOnError)
	argparse.Usage = func() {
		fmt.Fprintf(argparse.Output(), "Usage: rope [flags]\n")
	}
	configArg := argparse.String("config", "", "Specify the path to the config file.")
	argparse.Parse(os.Args[1:])
	var configPath string
	if configArg == nil {
		configPath = *configArg
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil { log.Fatal(err.Error()) }
		configPath = path.Join(homeDir, ".rope")
	}
	// read config file...
	var config *mdconf.MDConfSection
	configFile, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Cannot find any config file. Creating one...")
			config = initConfigAt(configPath)
		} else {
			log.Fatal(err.Error())
		}
	} else {
		config = mdconf.Parse(configFile)
		err = configFile.Close()
		if err != nil { log.Fatal(err.Error()) }
	}
	
	var socksv4Enable bool = false
	socksv4EnableStr, err := config.QueryKey(KEY_SOCKS_V4_ENABLE)
	if err != nil {
		log.Printf("Cannot determine whether to enable SOCKSv4: %s. For safety reasons it will not be enabled.", err.Error())
		socksv4Enable = false
	} else {
		socksv4Enable = socksv4EnableStr == "true"
	}
	socksv4BindAddr, err := config.QueryKey(KEY_SOCKS_V4_BINDADDR)
	socksv4BindPort, err := config.QueryKey(KEY_SOCKS_V4_BINDPORT)
	
	var socksv5Enable bool = false
	socksv5EnableStr, err := config.QueryKey(KEY_SOCKS_V5_ENABLE)
	if err != nil {
		log.Printf("Cannot determine whether to enable SOCKSv5: %s. For safety reasons it will not be enabled.", err.Error())
		socksv5Enable = false
	} else {
		socksv5Enable = socksv5EnableStr == "true"
	}
	socksv5BindAddr, err := config.QueryKey(KEY_SOCKS_V5_BINDADDR)
	socksv5BindPort, err := config.QueryKey(KEY_SOCKS_V5_BINDPORT)

	if socksv4BindPort == socksv5BindPort && socksv4BindAddr != socksv5BindAddr {
		log.Fatal("Cannot use the same port but have different bind address.")
	}

	var socksv4Listener net.Listener
	var socksv5Listener net.Listener

	if socksv4BindPort == socksv5BindPort {
		fulladdr := toFullAddr(socksv4BindAddr, socksv4BindPort)
		listener, err := net.Listen("tcp", fulladdr)
		if err != nil { log.Fatal(err) }
		socksv4Listener = listener
		socksv5Listener = listener
		log.Printf("[SOCKSv4] Listening on %s", fulladdr)
		log.Printf("[SOCKSv5] Listening on %s", fulladdr)
		go func(){
			for {
				conn, err := listener.Accept()
				log.Printf("Accepted: %s\n", conn.RemoteAddr().String())
				if err != nil { continue }
				go handleSocksClient(conn)
			}
		}()
	} else {
		if socksv4Enable {
			fulladdr := toFullAddr(socksv4BindAddr, socksv4BindPort)
			listener, err := net.Listen("tcp", fulladdr)
			if err != nil { log.Fatal(err) }
			socksv4Listener = listener
			log.Printf("[SOCKSv4] Listening on %s", fulladdr)
			go func(){
				for {
					conn, err := listener.Accept()
					if err != nil { continue }
					log.Printf("[SOCKSv4] Accepted: %s\n", conn.RemoteAddr().String())
					go handleSocksv4Only(conn)
				}
			}()
		}
		if socksv5Enable {
			fulladdr := toFullAddr(socksv5BindAddr, socksv5BindPort)
			listener, err := net.Listen("tcp", fulladdr)
			if err != nil { log.Fatal(err) }
			socksv5Listener = listener
			log.Printf("[SOCKSv5] Listening on %s", fulladdr)
			go func(){
				for {
					conn, err := listener.Accept()					
					if err != nil { continue }
					log.Printf("[SOCKSv5] Accepted: %s\n", conn.RemoteAddr().String())
					go handleSocksv5Only(conn)
				}
			}()
		}
	}

	// shutdown.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	socksv4Listener.Close()
	log.Println("[SOCKSv4] Closed")
	socksv5Listener.Close()
	log.Println("[SOCKSv5] Closed")
	
}

