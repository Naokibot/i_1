package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Naokibot/i_1/internal/api"
	"github.com/Naokibot/i_1/internal/engine"
	"github.com/Naokibot/i_1/internal/store"
)

func main() {
	listen := flag.String("listen", envOr("PQM_LISTEN", ":8080"), "HTTP listen address")
	dataPath := flag.String("data", envOr("PQM_DATA", "data/observatory.json"), "persistent JSON state file")
	sourceRoot := flag.String("source-root", envOr("PQM_SOURCE_ROOT", "."), "allowed root for source scans")
	flag.Parse()

	st, err := store.Open(*dataPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	eng, err := engine.New(st, *sourceRoot)
	if err != nil {
		log.Fatalf("create engine: %v", err)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.New(st, eng),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("PQM Observatory listening on %s", *listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutdown requested")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
