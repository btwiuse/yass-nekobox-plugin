package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	socks5 "github.com/things-go/go-socks5"
)

func TestParseProxyConfig_Basic(t *testing.T) {
	naive := NaiveConfig{
		Listen: "socks://127.0.0.1:1080",
		Proxy:  "https://user:pass@example.com:443",
	}
	cfg, err := parseProxyConfig(naive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerAddr != "example.com" {
		t.Errorf("ServerAddr = %q, want %q", cfg.ServerAddr, "example.com")
	}
	if cfg.ServerSNI != "example.com" {
		t.Errorf("ServerSNI = %q, want %q", cfg.ServerSNI, "example.com")
	}
	if cfg.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want %d", cfg.ServerPort, 443)
	}
	if cfg.Username != "user" {
		t.Errorf("Username = %q, want %q", cfg.Username, "user")
	}
	if cfg.Password != "pass" {
		t.Errorf("Password = %q, want %q", cfg.Password, "pass")
	}
}

func TestParseProxyConfig_DefaultPort(t *testing.T) {
	naive := NaiveConfig{
		Listen: "socks://127.0.0.1:1080",
		Proxy:  "https://user:pass@example.com",
	}
	cfg, err := parseProxyConfig(naive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want 443", cfg.ServerPort)
	}
}

func TestParseProxyConfig_DefaultPortHTTP(t *testing.T) {
	naive := NaiveConfig{
		Listen: "socks://127.0.0.1:1080",
		Proxy:  "http://user:pass@example.com",
	}
	cfg, err := parseProxyConfig(naive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerPort != 80 {
		t.Errorf("ServerPort = %d, want 80", cfg.ServerPort)
	}
}

func TestParseProxyConfig_HostResolverRules(t *testing.T) {
	naive := NaiveConfig{
		Listen:            "socks://127.0.0.1:1080",
		Proxy:             "https://user:pass@example.com:443",
		HostResolverRules: "MAP example.com 192.168.1.1",
	}
	cfg, err := parseProxyConfig(naive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerAddr != "192.168.1.1" {
		t.Errorf("ServerAddr = %q, want %q", cfg.ServerAddr, "192.168.1.1")
	}
	if cfg.ServerSNI != "example.com" {
		t.Errorf("ServerSNI = %q, want %q (must remain original hostname)", cfg.ServerSNI, "example.com")
	}
}

func TestParseProxyConfig_InvalidURL(t *testing.T) {
	naive := NaiveConfig{
		Listen: "socks://127.0.0.1:1080",
		Proxy:  "://invalid",
	}
	_, err := parseProxyConfig(naive)
	if err == nil {
		t.Fatal("expected error for invalid proxy URL, got nil")
	}
}

// generateTestTLSConfig creates a self-signed TLS certificate and returns
// the server TLS config and a client TLS config that trusts it.
func generateTestTLSConfig(t *testing.T) (serverTLS *tls.Config, clientTLS *tls.Config) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	pool := x509.NewCertPool()
	parsedCert, _ := x509.ParseCertificate(certDER)
	pool.AddCert(parsedCert)

	serverTLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	clientTLS = &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	}
	return
}

// startMockHTTPSConnectProxy starts a TLS server that handles HTTP CONNECT
// requests and relays data to the target.
func startMockHTTPSConnectProxy(t *testing.T, wantUser, wantPass string) (addr string, clientTLS *tls.Config, cleanup func()) {
	t.Helper()

	serverTLS, clientTLS := generateTestTLSConfig(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleProxyConn(conn, wantUser, wantPass)
		}
	}()

	return ln.Addr().String(), clientTLS, func() { ln.Close() }
}

func handleProxyConn(conn net.Conn, wantUser, wantPass string) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		resp := &http.Response{StatusCode: http.StatusMethodNotAllowed, ProtoMajor: 1, ProtoMinor: 1}
		resp.Write(conn)
		return
	}

	if wantUser != "" {
		auth := req.Header.Get("Proxy-Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(wantUser+":"+wantPass))
		if auth != expected {
			resp := &http.Response{StatusCode: http.StatusProxyAuthRequired, ProtoMajor: 1, ProtoMinor: 1}
			resp.Write(conn)
			return
		}
	}

	target, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
	if err != nil {
		resp := &http.Response{StatusCode: http.StatusBadGateway, ProtoMajor: 1, ProtoMinor: 1}
		resp.Write(conn)
		return
	}
	defer target.Close()

	fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, target); done <- struct{}{} }()
	<-done
}

// startEchoServer starts a simple TCP server that echoes received data.
func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// makeHTTPSConnectDialerWithTLSConfig is a test helper that allows overriding the TLS config.
func makeHTTPSConnectDialerWithTLSConfig(cfg *ProxyConfig, tlsConfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyAddr := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)
	basicAuth := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &tls.Dialer{Config: tlsConfig}
		tlsConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("TLS dial to proxy: %w", err)
		}

		connectReq := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if cfg.Username != "" {
			connectReq.Header.Set("Proxy-Authorization", "Basic "+basicAuth)
		}
		if err := connectReq.Write(tlsConn); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("write CONNECT request: %w", err)
		}

		br := bufio.NewReader(tlsConn)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("read CONNECT response: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			tlsConn.Close()
			return nil, fmt.Errorf("proxy CONNECT returned status %d", resp.StatusCode)
		}

		if br.Buffered() > 0 {
			return &bufferedConn{Reader: br, Conn: tlsConn}, nil
		}
		return tlsConn, nil
	}
}

func TestEndToEnd_SOCKS5_via_HTTPSConnect(t *testing.T) {
	// 1. Start an echo server (the "internet" target)
	echoAddr, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	// 2. Start a mock HTTPS CONNECT proxy
	proxyAddr, clientTLS, proxyCleanup := startMockHTTPSConnectProxy(t, "testuser", "testpass")
	defer proxyCleanup()

	proxyHost, proxyPortStr, _ := net.SplitHostPort(proxyAddr)

	// 3. Create a SOCKS5 server with our HTTPS CONNECT dialer
	cfg := &ProxyConfig{
		ServerAddr: proxyHost,
		ServerSNI:  proxyHost,
		ServerPort: mustAtoi(proxyPortStr),
		Username:   "testuser",
		Password:   "testpass",
	}

	dialer := makeHTTPSConnectDialerWithTLSConfig(cfg, clientTLS)

	socksServer := socks5.NewServer(
		socks5.WithDial(dialer),
	)

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for SOCKS5: %v", err)
	}
	defer socksLn.Close()

	go socksServer.Serve(socksLn)

	// 4. Connect through SOCKS5 to the echo server
	socksAddr := socksLn.Addr().String()
	conn, err := dialViaSocks5(socksAddr, echoAddr)
	if err != nil {
		t.Fatalf("failed to connect via SOCKS5: %v", err)
	}
	defer conn.Close()

	// 5. Send data and verify echo
	testMsg := "hello from socks5 via https connect proxy\n"
	if _, err := conn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if string(buf) != testMsg {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), testMsg)
	}
}

func TestHTTPSConnectDialer_AuthFailure(t *testing.T) {
	proxyAddr, clientTLS, proxyCleanup := startMockHTTPSConnectProxy(t, "correctuser", "correctpass")
	defer proxyCleanup()

	proxyHost, proxyPortStr, _ := net.SplitHostPort(proxyAddr)

	cfg := &ProxyConfig{
		ServerAddr: proxyHost,
		ServerSNI:  proxyHost,
		ServerPort: mustAtoi(proxyPortStr),
		Username:   "wronguser",
		Password:   "wrongpass",
	}

	dialer := makeHTTPSConnectDialerWithTLSConfig(cfg, clientTLS)

	_, err := dialer(context.Background(), "tcp", "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected auth failure error, got nil")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Errorf("expected status 407 in error, got: %v", err)
	}
}

// dialViaSocks5 connects to the given target address through a local SOCKS5 proxy.
func dialViaSocks5(socksAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// SOCKS5 handshake: no auth
	conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}

	// SOCKS5 CONNECT request
	host, portStr, _ := net.SplitHostPort(targetAddr)
	portInt := mustAtoi(portStr)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(portInt>>8), byte(portInt&0xff))
	conn.Write(req)

	// Read SOCKS5 response (min 10 bytes for IPv4 reply)
	respBuf := make([]byte, 10)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		conn.Close()
		return nil, err
	}
	if respBuf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed with code %d", respBuf[1])
	}

	return conn, nil
}

func mustAtoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
