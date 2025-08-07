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

type GlobalContext struct {
	Config *mdconf.MDConfSection
	SOCKSv5UserDatabase UserDatabase
}


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
	v5.LocalSetKey(LOCAL_KEY_USEAUTH, "false")
	v5.LocalSetKey(LOCAL_KEY_USERDATABASE, "")
    clientMode, _ := socks.LocalAddSection("clientMode")
	clientMode.LocalSetKey("enable", "false")
	clientMode.LocalSetKey("serverAddr", "")
	clientMode.LocalSetKey("serverPort", "")
	clientMode.LocalSetKey("username", "")
	clientMode.LocalSetKey("password", "")
	os.WriteFile(configPath, []byte(res.ToString()), 0644)
	return res
}

func handleSocks4(gctx *GlobalContext, buf []byte, conn net.Conn) {
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

func handleSocks5(gctx *GlobalContext, buf []byte, conn net.Conn) {
	var useAuth bool
	useAuthStr, err := gctx.Config.QueryKey(KEY_SOCKS_V5_USEAUTH)
	if err != nil || useAuthStr != "true" {
		useAuth = false
	} else {
		useAuth = true
		log.Printf("[SOCKSv5] username/password auth enabled according to conf | %s\n", conn.RemoteAddr())
	}
	if useAuth {
		canUseAuth := false
		for i := range buf[1] {
			if buf[2+i] == 0x02 { canUseAuth = true; break }
		}
		if !canUseAuth {
			conn.Write([]byte{0x05, 0xff})
			log.Printf("[SOCKSv5] client failed to support username auth | %s\n", conn.RemoteAddr())
			return
		}
		_, err := conn.Read(buf)
		if err != nil {
			conn.Write([]byte{0x01, 0xff})
			return
		}
		ulen := int(buf[1])
		username := buf[2:2+ulen]
		plen := int(buf[2+ulen])
		password := buf[2+ulen+1:2+ulen+1+plen]
		log.Printf("[SOCKSv5] client requested auth for ==%s== | %s\n", username, conn.RemoteAddr())
		chkres := gctx.SOCKSv5UserDatabase.Check(string(username), string(password))
		if chkres != nil {
			conn.Write([]byte{0x01, 0xff})
			log.Printf("[SOCKSv5] client failed username/password check | %s\n", conn.RemoteAddr())
			return
		}
		conn.Write([]byte{0x01, 0x00})
	}
	
	i := 1
	// ignore everything & use no auth.
	conn.Write([]byte{0x05, 0x00})
	_, err = conn.Read(buf)
	if err != nil {
		conn.Write([]byte{0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
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

func handleSocksClient(gctx *GlobalContext, conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return
	}

	switch buf[0] {
	case 4: // socks 4
		handleSocks4(gctx, buf, conn)
	case 5: // socks
		handleSocks5(gctx, buf, conn)
	}

}

func handleSocksv4Only(gctx *GlobalContext, conn  net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 9 { return }
	if buf[0] == 4 { handleSocks4(gctx, buf, conn) }
}

func handleSocksv5Only(gctx *GlobalContext, conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 3 { return }
	if buf[0] == 5 { handleSocks5(gctx, buf, conn) }
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
	if configArg != nil && (len(*configArg) > 0) {
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
	gctx := &GlobalContext{
		Config: config,
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

	if socksv5Enable {
		useAuthStr, err := config.QueryKey(KEY_SOCKS_V5_USEAUTH)
		if err == nil && useAuthStr == "true" {
			userdbPath, err := config.QueryKey(KEY_SOCKS_V5_USERDATABASE)
			if err == nil {
				db, err := loadUserDatabase(userdbPath)
				if err == nil {
					gctx.SOCKSv5UserDatabase = db
				}
			}
		}
	}

	var socksv4Listener net.Listener
	var socksv5Listener net.Listener
	if socksv4BindPort == socksv5BindPort {
		// this is slightly more complicated because some client would
		// send v4 and v5 messages to the same port even if configured
		// to be v4 only.  (looking at you, SwitchyOmega)
		fulladdr := toFullAddr(socksv4BindAddr, socksv4BindPort)
		listener, err := net.Listen("tcp", fulladdr)
		if err != nil { log.Fatal(err) }
		if socksv4Enable && socksv5Enable {
			socksv4Listener = listener
			socksv5Listener = listener
			log.Printf("[SOCKSv4] Listening on %s", fulladdr)
			log.Printf("[SOCKSv5] Listening on %s", fulladdr)
			go func(){
				for {
					conn, err := listener.Accept()
					log.Printf("Accepted: %s\n", conn.RemoteAddr().String())
					if err != nil { continue }
					go handleSocksClient(gctx, conn)
				}
			}()
		} else if socksv4Enable {
			socksv4Listener = listener
			log.Printf("[SOCKSv4] Listening on %s", fulladdr)
			go func(){
				for {
					conn, err := listener.Accept()
					if err != nil { continue }
					log.Printf("[SOCKSv4] Accepted: %s\n", conn.RemoteAddr().String())
					go handleSocksv4Only(gctx, conn)
				}
			}()
		} else if socksv5Enable {
			socksv5Listener = listener
			log.Printf("[SOCKSv5] Listening on %s", fulladdr)
			go func(){
				for {
					conn, err := listener.Accept()					
					if err != nil { continue }
					log.Printf("[SOCKSv5] Accepted: %s\n", conn.RemoteAddr().String())
					go handleSocksv5Only(gctx, conn)
				}
			}()
		}
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
					go handleSocksv4Only(gctx, conn)
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
					go handleSocksv5Only(gctx, conn)
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

