package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Naokibot/i_1/internal/api"
	"github.com/Naokibot/i_1/internal/engine"
	"github.com/Naokibot/i_1/internal/store"
)

const minimumAPITokenLength = 32

func main() {
	listen := flag.String("listen", envOr("PQM_LISTEN", "127.0.0.1:8080"), "HTTP listen address")
	dataPath := flag.String("data", envOr("PQM_DATA", "data/observatory.json"), "persistent JSON state file")
	sourceRoot := flag.String("source-root", envOr("PQM_SOURCE_ROOT", "."), "allowed root for source scans")
	apiToken := flag.String("api-token", os.Getenv("PQM_API_TOKEN"), "bearer token protecting the API")
	flag.Parse()

	if err := validateListenSecurity(*listen, *apiToken); err != nil {
		log.Fatalf("unsafe listen configuration: %v", err)
	}

	st, err := store.Open(*dataPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	eng, err := engine.New(st, *sourceRoot)
	if err != nil {
		log.Fatalf("create engine: %v", err)
	}
	srv := &http.Server{
		Addr: *listen,
		Handler: api.NewWithOptions(st, eng, api.Options{
			BearerToken: *apiToken,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	serverError := make(chan error, 1)
	go func() {
		log.Printf("PQM Observatory listening on %s", *listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverError <- err
		}
		close(serverError)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-stop:
		log.Printf("shutdown requested by %s", sig)
	case err := <-serverError:
		if err != nil {
			log.Fatalf("server: %v", err)
		}
		return
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownContext); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		_ = srv.Close()
	}
}

func validateListenSecurity(address, token string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if isLoopbackHost(host) {
		return nil
	}
	if len(token) < minimumAPITokenLength {
		return fmt.Errorf("PQM_API_TOKEN must contain at least %d characters when listening beyond loopback", minimumAPITokenLength)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
