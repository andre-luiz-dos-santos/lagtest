// lagtest server: measures per-UDP-port packet loss to diagnose LACP links.
//
// Control protocol (TCP, one text line per message):
//
//	S: NONCE <hex>
//	C: AUTH <sha256hex(nonce + password)>
//	S: OK <token> <udpBase> <numPorts>          (connection closed on bad auth)
//	C: MODE send|recv                           (direction from the client's view)
//	S: READY
//
//	send: client sends UDP to udpBase..udpBase+99, each packet prefixed with
//	      the token; when done it sends DONE and the server answers
//	      RESULT <recv count per port ...>.
//	recv: client punches the server ports with token packets so the server
//	      learns the 100 return addresses, polling with PUNCHED (answered by
//	      MISS <indices of ports still unknown>) until all are confirmed,
//	      then sends GO; the server bursts the packets back to the punched
//	      ports and sends SENT when finished.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	numPorts   = 100
	packetSize = 1400
	loops      = 100
	loopSleep  = 50 * time.Millisecond
	tokenLen   = 16 // hex chars prefixing every UDP packet
)

type session struct {
	mu     sync.Mutex
	mode   string
	counts [numPorts]int          // packets received per port (send mode)
	addrs  [numPorts]*net.UDPAddr // client return addresses (recv mode)
}

var (
	sessions   = map[string]*session{}
	sessionsMu sync.Mutex
	udpConns   [numPorts]*net.UDPConn
)

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// udpReader dispatches packets arriving on port index i to their session,
// identified by the token prefix. Unknown tokens are dropped silently.
func udpReader(i int) {
	buf := make([]byte, packetSize+100)
	for {
		n, addr, err := udpConns[i].ReadFromUDP(buf)
		if err != nil || n < tokenLen {
			continue
		}
		sessionsMu.Lock()
		s := sessions[string(buf[:tokenLen])]
		sessionsMu.Unlock()
		if s == nil {
			continue
		}
		s.mu.Lock()
		if s.mode == "send" {
			s.counts[i]++
		} else {
			s.addrs[i] = addr // hole-punch packet: remember where to send
		}
		s.mu.Unlock()
	}
}

func handle(c net.Conn, password string, udpBase int) {
	defer c.Close()
	// short deadline until authenticated so strangers can't hog a slot
	c.SetDeadline(time.Now().Add(10 * time.Second))
	in := bufio.NewScanner(c)
	in.Buffer(make([]byte, 256), 4096) // protocol lines are tiny; cap per-conn memory
	line := func() []string {
		if !in.Scan() {
			return nil
		}
		return strings.Fields(in.Text())
	}

	nonce := randHex(16)
	fmt.Fprintf(c, "NONCE %s\n", nonce)
	auth := line()
	want := sha256Hex(nonce + password)
	if len(auth) != 2 || auth[0] != "AUTH" ||
		subtle.ConstantTimeCompare([]byte(auth[1]), []byte(want)) != 1 {
		return
	}

	c.SetDeadline(time.Now().Add(2 * time.Minute))
	token := randHex(tokenLen / 2)
	s := &session{}
	sessionsMu.Lock()
	sessions[token] = s
	sessionsMu.Unlock()
	defer func() {
		sessionsMu.Lock()
		delete(sessions, token)
		sessionsMu.Unlock()
	}()
	fmt.Fprintf(c, "OK %s %d %d\n", token, udpBase, numPorts)

	mode := line()
	if len(mode) != 2 || mode[0] != "MODE" || (mode[1] != "send" && mode[1] != "recv") {
		return
	}
	s.mu.Lock()
	s.mode = mode[1]
	s.mu.Unlock()
	log.Printf("client %s started test (mode %s)", c.RemoteAddr(), mode[1])
	defer log.Printf("client %s finished test (mode %s)", c.RemoteAddr(), mode[1])
	fmt.Fprintln(c, "READY")

	if mode[1] == "send" {
		if cmd := line(); len(cmd) == 1 && cmd[0] == "DONE" {
			s.mu.Lock()
			parts := make([]string, numPorts)
			for i, n := range s.counts {
				parts[i] = strconv.Itoa(n)
			}
			s.mu.Unlock()
			fmt.Fprintf(c, "RESULT %s\n", strings.Join(parts, " "))
		}
	} else {
		// punch phase: answer PUNCHED queries with the not-yet-known ports
		// until the client is satisfied and sends GO
		for {
			cmd := line()
			if len(cmd) == 0 {
				return
			}
			if cmd[0] == "GO" {
				break
			}
			miss := []string{"MISS"}
			s.mu.Lock()
			for i, a := range s.addrs {
				if a == nil {
					miss = append(miss, strconv.Itoa(i))
				}
			}
			s.mu.Unlock()
			fmt.Fprintln(c, strings.Join(miss, " "))
		}
		pkt := make([]byte, packetSize)
		copy(pkt, token)
		s.mu.Lock()
		addrs := s.addrs // ports whose punch packet was lost stay nil: 100% loss
		s.mu.Unlock()
		for l := 0; l < loops; l++ {
			for i, a := range addrs {
				if a != nil {
					udpConns[i].WriteToUDP(pkt, a)
				}
			}
			time.Sleep(loopSleep)
		}
		fmt.Fprintln(c, "SENT")
	}
}

func main() {
	listen := flag.String("listen", ":6300", "TCP control address")
	udpBase := flag.Int("udp", 6301, "first of the 100 consecutive UDP ports")
	password := flag.String("password", "", "shared password (required)")
	flag.Parse()
	if *password == "" {
		log.Fatal("-password is required")
	}

	for i := range udpConns {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *udpBase + i})
		if err != nil {
			log.Fatalf("udp port %d: %v", *udpBase+i, err)
		}
		udpConns[i] = conn
		go udpReader(i)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	sem := make(chan struct{}, 64) // cap concurrent control connections
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err) // e.g. EMFILE under a connection flood
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				handle(c, *password, *udpBase)
			}()
		default:
			c.Close()
		}
	}
}
