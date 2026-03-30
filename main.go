package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	socks5 "github.com/things-go/go-socks5"
)

// NaiveConfig defines the NaiveProxy config structure passed by NekoBox.
type NaiveConfig struct {
	Listen            string `json:"listen"`
	Proxy             string `json:"proxy"`
	HostResolverRules string `json:"host-resolver-rules,omitempty"`
}

// ProxyConfig holds parsed proxy connection parameters.
type ProxyConfig struct {
	ServerAddr string // IP or hostname to connect to (may be overridden by HostResolverRules)
	ServerSNI  string // TLS SNI (always the original hostname)
	ServerPort int
	Username   string
	Password   string
}

func main() {
	var configPath string
	if len(os.Args) > 1 {
		configPath = os.Args[len(os.Args)-1]
	}
	if configPath == "" || !strings.HasSuffix(configPath, ".json") {
		log.Fatalf("Error: no JSON config file path found. Args: %v", os.Args)
	}

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var naive NaiveConfig
	if err := json.Unmarshal(configBytes, &naive); err != nil {
		log.Fatalf("Failed to parse config JSON: %v", err)
	}

	listenURL, err := url.Parse(naive.Listen)
	if err != nil {
		log.Fatalf("Failed to parse Listen URL: %v", err)
	}
	listenAddr := net.JoinHostPort(listenURL.Hostname(), listenURL.Port())

	proxyCfg, err := parseProxyConfig(naive)
	if err != nil {
		log.Fatalf("Failed to parse proxy config: %v", err)
	}

	server := socks5.NewServer(
		socks5.WithDial(makeHTTPSConnectDialer(proxyCfg)),
	)

	log.Printf("Starting SOCKS5 server on %s, proxying via %s:%d (SNI: %s)",
		listenAddr, proxyCfg.ServerAddr, proxyCfg.ServerPort, proxyCfg.ServerSNI)

	if err := server.ListenAndServe("tcp", listenAddr); err != nil {
		log.Fatalf("SOCKS5 server failed: %v", err)
	}
}

// parseProxyConfig extracts proxy connection parameters from a NaiveConfig.
func parseProxyConfig(naive NaiveConfig) (*ProxyConfig, error) {
	proxyURL, err := url.Parse(naive.Proxy)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}

	serverPort, _ := strconv.Atoi(proxyURL.Port())
	if serverPort == 0 {
		if proxyURL.Scheme == "https" {
			serverPort = 443
		} else {
			serverPort = 80
		}
	}

	username := proxyURL.User.Username()
	password, _ := proxyURL.User.Password()

	serverAddr := proxyURL.Hostname()
	if naive.HostResolverRules != "" {
		parts := strings.Split(naive.HostResolverRules, " ")
		if len(parts) >= 3 && parts[0] == "MAP" {
			serverAddr = parts[2]
		}
	}

	return &ProxyConfig{
		ServerAddr: serverAddr,
		ServerSNI:  proxyURL.Hostname(),
		ServerPort: serverPort,
		Username:   username,
		Password:   password,
	}, nil
}

// makeHTTPSConnectDialer returns a dial function that tunnels connections
// through a remote HTTPS CONNECT proxy.
func makeHTTPSConnectDialer(cfg *ProxyConfig) func(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(cfg.ServerAddr, strconv.Itoa(cfg.ServerPort))
	basicAuth := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &tls.Dialer{
			Config: &tls.Config{
				ServerName: cfg.ServerSNI,
			},
		}
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

// bufferedConn wraps a net.Conn with a bufio.Reader to drain any data
// buffered during the HTTP CONNECT handshake before reading from the
// underlying connection directly.
type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}
