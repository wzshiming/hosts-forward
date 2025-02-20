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
	pflag.StringVar(&defaultEndpoint, "default-endpoint", defaultEndpoint, "default endpoint")
	pflag.StringToStringVar(&endpoints, "endpoint", endpoints, "endpoint")
	pflag.StringVar(&blockEndpoint, "block-endpoint", blockEndpoint, "block endpoint")
	pflag.Parse()
}

func main() {
	ctx := context.Background()

	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		slog.Error("Failed to listen port", "err", err)
		os.Exit(1)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				slog.Error("Failed to accept conn", "err", err)
				os.Exit(1)
			}
			var dialer net.Dialer
			slog.Info("come conn", "from", splitHost(conn.RemoteAddr().String()))
			go forward(ctx, &dialer, conn)
		}
	}()

	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		if r.URL.Host == "" {
			r.URL.Host = r.Host
		}
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}))

	err = http.ListenAndServe(":80", nil)
	if err != nil {
		slog.Error("Failed to start http", "err", err)
		os.Exit(1)
	}
}

func forward(ctx context.Context, dialer *net.Dialer, conn net.Conn) {
	buf := bytes.NewBuffer(nil)
	defer conn.Close()

	from := splitHost(conn.RemoteAddr().String())

	tmpReader := io.TeeReader(conn, buf)
	host, err := sni.TLSHost(tmpReader)
	if err != nil {
		slog.Warn("failed to get host", "from", from, "err", err)
		return
	}

	address := defaultEndpoint
	if e, ok := endpoints[host]; ok {
		address = e
	}
	if address == "" {
		address = host
	}

	if e, err := getHostAddress(address); err != nil {
		slog.Warn("failed to get address", "target", address, "from", from, "host", host, "err", err)
		return
	} else {
		address = e
	}

	if address == blockEndpoint {
		slog.Info("block", "target", address, "from", from, "host", host)
		return
	}

	slog.Info("forward", "target", address, "from", from)
	forward, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, "443"))
	if err != nil {
		slog.Warn("failed to dial target", "target", address, "from", from, "host", host, "err", err)
		return
	}
	defer forward.Close()

	err = tunnel(ctx, cmux.UnreadConn(conn, buf.Bytes()), forward)
	if err != nil {
		slog.Warn("end forwarding", "target", address, "from", from, "host", host, "err", err)
		return
	}
	slog.Info("done", "target", address, "from", from, "host", host)
}

func tunnel(ctx context.Context, c1, c2 io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
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

type tunnelErr [5]error

func (t tunnelErr) FirstError() error {
	for _, err := range t {
		if err != nil {
			return err
		}
	}
	return nil
}

func splitHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

var cacheAddr sync.Map

func getHostAddress(host string) (string, error) {
	host = splitHost(host)

	names, err := net.LookupIP(host)
	if err != nil {
		a, ok := cacheAddr.Load(host)
		if !ok {
			return "", err
		}
		names = a.([]net.IP)
	} else {
		cacheAddr.Store(host, names)
		slog.Info("lookup", "names", names)
	}

	return names[rand.Int63n(int64(len(names)))].String(), nil
}
