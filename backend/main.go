package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"blue-siem/internal/api"
	"blue-siem/internal/engine"
	"blue-siem/internal/store"
	"blue-siem/internal/syslog"
	"blue-siem/web"
)

const version = "0.1.0"

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	httpAddr := flag.String("http", env("SIEM_HTTP", ":8080"), "HTTP listen address (web UI and REST API)")
	udpAddr := flag.String("udp", env("SIEM_SYSLOG_UDP", ":5514"), "syslog UDP listen address (empty to disable)")
	tcpAddr := flag.String("tcp", env("SIEM_SYSLOG_TCP", ":5514"), "syslog TCP listen address (empty to disable)")
	dbPath := flag.String("db", env("SIEM_DB", "siem.db"), "SQLite database file")
	flag.Parse()

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	eng := engine.New(db)
	if err := eng.Reload(); err != nil {
		log.Fatalf("engine: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go eng.Run(ctx)

	if *udpAddr != "" {
		if err := syslog.ListenUDP(ctx, *udpAddr, eng.Enqueue); err != nil {
			log.Fatalf("syslog udp: %v", err)
		}
		log.Printf("syslog UDP listening on %s", *udpAddr)
	}
	if *tcpAddr != "" {
		if err := syslog.ListenTCP(ctx, *tcpAddr, eng.Enqueue); err != nil {
			log.Fatalf("syslog tcp: %v", err)
		}
		log.Printf("syslog TCP listening on %s", *tcpAddr)
	}

	info := api.Info{SyslogUDP: *udpAddr, SyslogTCP: *tcpAddr, Version: version}
	srv := &http.Server{
		Addr:              *httpAddr,
		Handler:           api.NewRouter(db, eng, info, web.FS()),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	log.Printf("web UI on http://localhost%s", *httpAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("http: %v", err)
	}
}
