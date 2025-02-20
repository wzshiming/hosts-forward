package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/spf13/pflag"
	"github.com/wzshiming/cmux"
	"github.com/wzshiming/sni"
)

var (
	defaultEndpoint string
	endpoints       map[string]string
	blockEndpoint   string
)

func init() {
	pflag.StringVar(&defaultEndpoint, "default-endpoint", defaultEndpoint, "Default endpoint for forwarding")
	pflag.StringToStringVar(&endpoints, "endpoint", endpoints, "Host-specific endpoints mapping")
	pflag.StringVar(&blockEndpoint, "block-endpoint", blockEndpoint, "Endpoint to block requests for")
	pflag.Parse()
}

func main() {
	ctx := context.Background()

	// Start TLS listener
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		slog.Error("Failed to listen on port 443", "err", err)
		os.Exit(1)
	}

	// Start HTTP->HTTPS redirector
	go startRedirector()

	// Handle incoming TLS connections
	go startListener(ctx, listener)

	// Block main goroutine
	select {}
}

func startListener(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("Connection accept failed", "err", err)
			os.Exit(1)
		}

		from := splitHost(conn.RemoteAddr().String())
		slog.Info("New connection", "from", from)
		go handleConnection(ctx, conn, from)
	}
}

func startRedirector() {
	http.Handle("/", http.HandlerFunc(redirectToHTTPS))

	if err := http.ListenAndServe(":80", nil); err != nil {
		slog.Error("HTTP server failed", "err", err)
		os.Exit(1)
	}
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	r.URL.Scheme = "https"
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}

func handleConnection(ctx context.Context, conn net.Conn, from string) {
	defer conn.Close()

	// Read SNI host from connection
	buf := bytes.NewBuffer(nil)
	host, err := sni.TLSHost(io.TeeReader(conn, buf))
	if err != nil {
		slog.Warn("Failed to parse SNI", "from", from, "err", err)
		return
	}

	// Determine target address
	targetAddr, err := determineTargetAddress(host, from)
	if err != nil {
		slog.Warn("Failed to resolve target", "host", host, "from", from, "err", err)
		return
	}

	// Handle blocking
	if targetAddr == blockEndpoint {
		slog.Info("Blocked connection", "host", host, "from", from)
		return
	}

	// Establish forward connection
	forwardConn, err := net.Dial("tcp", net.JoinHostPort(targetAddr, "443"))
	if err != nil {
		slog.Warn("Failed to connect to target", "target", targetAddr, "host", host, "from", from, "err", err)
		return
	}
	defer forwardConn.Close()

	// Start proxying
	slog.Info("Forwarding connection", "target", targetAddr, "host", host, "from", from)
	if err := tunnel(ctx, cmux.UnreadConn(conn, buf.Bytes()), forwardConn); err != nil {
		slog.Warn("Forwarding error", "target", targetAddr, "host", host, "from", from, "err", err)
		return
	}
	slog.Info("Connection completed", "target", targetAddr, "host", host, "from", from)
}

func determineTargetAddress(host, from string) (string, error) {
	// Check endpoint mappings
	address := defaultEndpoint
	if e, ok := endpoints[host]; ok {
		address = e
	}
	if address == "" {
		address = host
	}

	// Resolve actual IP address
	resolvedAddr, err := getHostAddress(address)
	if err != nil {
		return "", err
	}
	return resolvedAddr, nil
}

// Connection tunneling logic
type tunnelErr [5]error

func (t tunnelErr) FirstError() error {
	for _, err := range t {
		if err != nil {
			return err
		}
	}
	return nil
}

func tunnel(ctx context.Context, c1, c2 io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var errs tunnelErr

	go func() {
		_, errs[0] = io.Copy(c1, c2)
		cancel()
	}()

	go func() {
		_, errs[1] = io.Copy(c2, c1)
		cancel()
	}()

	<-ctx.Done()

	errs[2] = c1.Close()
	errs[3] = c2.Close()
	errs[4] = ctx.Err()
	if errs[4] == context.Canceled {
		errs[4] = nil
	}

	return errs.FirstError()
}

// DNS resolution with caching
var ipCache sync.Map

func getHostAddress(host string) (string, error) {
	host = splitHost(host)

	ips, err := net.LookupIP(host)
	if err != nil {
		cached, ok := ipCache.Load(host)
		if !ok {
			return "", err
		}
		ips = cached.([]net.IP)
	} else {
		ipCache.Store(host, ips)
		slog.Debug("DNS lookup", "host", host, "ips", ips)
	}
	if len(ips) == 1 {
		return ips[0].String(), nil
	}

	return ips[rand.Int63n(int64(len(ips)))].String(), nil
}

// Helper functions
func splitHost(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	return hostPort
}
