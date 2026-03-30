package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

// NaiveConfig defines the NaiveProxy configuration structure from NekoBox
type NaiveConfig struct {
	Listen            string `json:"listen"`
	Proxy             string `json:"proxy"`
	HostResolverRules string `json:"host-resolver-rules,omitempty"`
}

// proxyConfig holds the parsed proxy settings
type proxyConfig struct {
	localAddr  string
	serverAddr string
	serverSNI  string
	serverPort int
	username   string
	password   string
}

func main() {
	// 1. Get the config file path from NekoBox
	var configPath string
	if len(os.Args) > 1 {
		configPath = os.Args[len(os.Args)-1]
	}

	if configPath == "" || !strings.HasSuffix(configPath, ".json") {
		log.Fatalf("Error: JSON config file path not found. Args: %v", os.Args)
	}

	// 2. Read and parse the NaiveProxy config
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	var naive NaiveConfig
	if err := json.Unmarshal(configBytes, &naive); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// 3. Parse listen address (e.g., socks://127.0.0.1:1080)
	listenURL, err := url.Parse(naive.Listen)
	if err != nil {
		log.Fatalf("Failed to parse Listen URL: %v", err)
	}

	// 4. Parse proxy URL (e.g., https://user:pass@example.com:443)
	proxyURL, err := url.Parse(naive.Proxy)
	if err != nil {
		log.Fatalf("Failed to parse Proxy URL: %v", err)
	}
	serverPort, _ := strconv.Atoi(proxyURL.Port())
	if serverPort == 0 {
		if proxyURL.Scheme == "https" {
			serverPort = 443
		} else {
			serverPort = 80
		}
	}

	// 5. Handle host-resolver-rules for routing loop prevention
	serverAddr := proxyURL.Hostname()
	serverSNI := proxyURL.Hostname()
	if naive.HostResolverRules != "" {
		parts := strings.Split(naive.HostResolverRules, " ")
		if len(parts) >= 3 && parts[0] == "MAP" {
			serverAddr = parts[2]
		}
	}

	cfg := &proxyConfig{
		localAddr:  net.JoinHostPort(listenURL.Hostname(), listenURL.Port()),
		serverAddr: serverAddr,
		serverSNI:  serverSNI,
		serverPort: serverPort,
		username:   proxyURL.User.Username(),
	}
	cfg.password, _ = proxyURL.User.Password()

	// 6. Start SOCKS5 listener
	listener, err := net.Listen("tcp", cfg.localAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.localAddr, err)
	}
	defer listener.Close()
	log.Printf("SOCKS5 proxy listening on %s, forwarding via %s:%d (SNI: %s)",
		cfg.localAddr, cfg.serverAddr, cfg.serverPort, cfg.serverSNI)

	// Graceful shutdown on SIGTERM/SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleSOCKS5(conn, cfg)
	}
}

// socks5Reply sends a SOCKS5 reply with the given reply code
func socks5Reply(conn net.Conn, rep byte) {
	// VER=5, REP, RSV=0, ATYP=1(IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// handleSOCKS5 handles a single SOCKS5 connection
func handleSOCKS5(conn net.Conn, cfg *proxyConfig) {
	defer conn.Close()

	// --- SOCKS5 Handshake ---
	// Read version and number of auth methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 0x05 {
		return
	}

	// Read and discard method list
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Reply: no authentication required
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// --- SOCKS5 Request ---
	// Read VER, CMD, RSV, ATYP
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 { // Only CONNECT (0x01) supported
		socks5Reply(conn, 0x07) // Command not supported
		return
	}

	// Parse destination address
	var targetHost string
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		targetHost = net.IP(addr).String()
	case 0x03: // Domain name
		var domainLen [1]byte
		if _, err := io.ReadFull(conn, domainLen[:]); err != nil {
			return
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		targetHost = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		targetHost = net.IP(addr).String()
	default:
		socks5Reply(conn, 0x08) // Address type not supported
		return
	}

	// Read destination port
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf[:])
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	// --- Connect to HTTPS CONNECT proxy ---
	remoteAddr := net.JoinHostPort(cfg.serverAddr, strconv.Itoa(cfg.serverPort))
	tlsConn, err := tls.Dial("tcp", remoteAddr, &tls.Config{
		ServerName: cfg.serverSNI,
	})
	if err != nil {
		log.Printf("TLS dial to proxy failed: %v", err)
		socks5Reply(conn, 0x05) // Connection refused
		return
	}
	defer tlsConn.Close()

	// Build HTTP CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if cfg.username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(cfg.username + ":" + cfg.password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	if _, err := tlsConn.Write([]byte(connectReq)); err != nil {
		log.Printf("Failed to send CONNECT: %v", err)
		socks5Reply(conn, 0x05)
		return
	}

	// Read HTTP CONNECT response
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		log.Printf("Failed to read CONNECT response: %v", err)
		socks5Reply(conn, 0x05)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("CONNECT failed: %s", resp.Status)
		socks5Reply(conn, 0x05)
		return
	}

	// SOCKS5 success reply
	socks5Reply(conn, 0x00)

	// Relay data bidirectionally
	// Use br (buffered reader) for remote->local to handle any buffered data
	done := make(chan struct{})
	go func() {
		io.Copy(conn, br)
		close(done)
	}()
	io.Copy(tlsConn, conn)
	tlsConn.Close()
	<-done
}
