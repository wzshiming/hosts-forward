package main

import (
	"bytes"
	"context"
	"fmt"
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
	defaultEndpoint       string
	endpoints             map[string]string
	blockEndpoint         string
	blockFallbackEndpoint string
	sniFallbackEndpoint   string
)

func init() {
	pflag.StringVar(&defaultEndpoint, "default-endpoint", defaultEndpoint, "Default endpoint for forwarding")
	pflag.StringToStringVar(&endpoints, "endpoint", endpoints, "Host-specific endpoints mapping")
	pflag.StringVar(&blockEndpoint, "block-endpoint", blockEndpoint, "Endpoint to block requests for")
	pflag.StringVar(&blockFallbackEndpoint, "block-fallback-endpoint", blockFallbackEndpoint, "Fallback endpoint when blocking")
	pflag.StringVar(&sniFallbackEndpoint, "sni-fallback-endpoint", sniFallbackEndpoint, "Fallback endpoint when no sni")
	pflag.Parse()
}

func main() {
	// TODO: Supports graceful shutdown
	ctx := context.Background()

	go startRedirector()
	startListener(ctx)
}

func startListener(ctx context.Context) {
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		slog.Error("Failed to create listener", "err", err, "address", listener.Addr().String())
		os.Exit(1)
	}

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
		slog.Error("HTTP redirect server failed", "err", err)
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

var bufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(nil)
	},
}

func handleConnection(ctx context.Context, conn net.Conn, from string) {
	buf := bufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
		conn.Close()
	}()

	host, err := sni.TLSHost(io.TeeReader(conn, buf))
	if err != nil {
		if sniFallbackEndpoint == "" {
			conn.Close()
			slog.Warn("SNI parse failure", "from", from, "err", err)
			return
		}
		host = sniFallbackEndpoint
	}

	targetAddr, err := determineTargetAddress(host, from)
	if err != nil {
		slog.Warn("Target resolution failed", "host", host, "from", from, "err", err)
		return
	}

	if targetAddr == from {
		if sniFallbackEndpoint == "" {
			conn.Close()
			slog.Warn("Target address same as source", "host", host, "from", from)
			return
		}
		host = sniFallbackEndpoint
	}

	forwardConn, err := net.Dial("tcp", net.JoinHostPort(targetAddr, "443"))
	if err != nil {
		slog.Warn("Target connection failed", "target", targetAddr, "host", host, "from", from, "err", err)
		return
	}
	defer forwardConn.Close()

	slog.Info("Starting proxy tunnel", "target", targetAddr, "host", host, "from", from)
	if err := tunnel(ctx, cmux.UnreadConn(conn, buf.Bytes()), forwardConn); err != nil {
		slog.Warn("Proxy tunnel error", "target", targetAddr, "host", host, "from", from, "err", err)
		return
	}
	slog.Info("Connection finished", "target", targetAddr, "host", host, "from", from)
}

func determineTargetAddress(host, from string) (string, error) {
	address := defaultEndpoint
	if e, ok := endpoints[host]; ok {
		address = e
	}
	if address == "" {
		address = host
	}

	resolvedAddr, err := getHostAddress(address)
	if err != nil {
		return "", fmt.Errorf("dns resolution failed: %w", err)
	}

	if resolvedAddr == blockEndpoint {
		if blockFallbackEndpoint == "" {
			return "", fmt.Errorf("access blocked")
		}
		resolvedAddr, err = getHostAddress(blockFallbackEndpoint)
		if err != nil {
			return "", fmt.Errorf("dns resolution failed: %w", err)
		}
	}
	return resolvedAddr, nil
}

var bytesPool = sync.Pool{
	New: func() any {
		return make([]byte, 32*1024)
	},
}

var errChPool = sync.Pool{
	New: func() any {
		return make(chan error, 2)
	},
}

func drainCh(ch chan error) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func tunnel(ctx context.Context, c1, c2 io.ReadWriter) error {
	buf1 := bytesPool.Get().([]byte)
	buf2 := bytesPool.Get().([]byte)
	errCh := errChPool.Get().(chan error)
	drainCh(errCh)

	defer func() {
		bytesPool.Put(buf1)
		bytesPool.Put(buf2)

		drainCh(errCh)
		errChPool.Put(errCh)
	}()

	go func() {
		_, err := io.CopyBuffer(c1, c2, buf1)
		errCh <- err
	}()

	go func() {
		_, err := io.CopyBuffer(c2, c1, buf2)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

var ipCache sync.Map

func getHostAddress(host string) (string, error) {
	host = splitHost(host)

	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}

	var resolver net.Resolver
	ips, err := resolver.LookupIP(context.Background(), "ip4", host)
	if err != nil {
		if cached, ok := ipCache.Load(host); ok {
			ips = cached.([]net.IP)
		} else {
			return "", fmt.Errorf("dns lookup failed: %w", err)
		}
	} else {
		ipCache.Store(host, ips)
		slog.Debug("DNS cache updated", "host", host, "ips", ips)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no addresses found")
	}
	if len(ips) == 1 {
		return ips[0].String(), nil
	}

	// Random selection from available IPs
	return ips[rand.Int63n(int64(len(ips)))].String(), nil
}

func splitHost(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	return hostPort
}
