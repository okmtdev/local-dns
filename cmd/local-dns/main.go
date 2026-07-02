// Command local-dns is a small DNS service for home networks: it
// tracks devices on the LAN by MAC address, serves DNS names that
// always point at each device's current IP, and offers a web UI to
// manage the assignments.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/okmtdev/local-dns/internal/config"
	"github.com/okmtdev/local-dns/internal/dnsserver"
	"github.com/okmtdev/local-dns/internal/scanner"
	"github.com/okmtdev/local-dns/internal/store"
	"github.com/okmtdev/local-dns/internal/web"
)

var version = "dev" // overridden via -ldflags "-X main.version=..."

const flushInterval = 10 * time.Minute

func main() {
	configPath := flag.String("config", "/etc/local-dns/config.conf", "設定ファイルのパス")
	showVersion := flag.Bool("version", false, "バージョンを表示して終了")
	debug := flag.Bool("debug", false, "デバッグログを有効化")
	flag.Parse()

	if *showVersion {
		fmt.Println("local-dns", version)
		return
	}

	cfg, found, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if !found {
		log.Info("config file not found, using defaults", "path", *configPath)
	}

	if err := run(cfg, log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, log *slog.Logger) error {
	onlineWindow := 3 * cfg.ScanInterval
	if onlineWindow < 90*time.Second {
		onlineWindow = 90 * time.Second
	}

	st, err := store.Open(cfg.StatePath, onlineWindow)
	if errors.Is(err, store.ErrCorrupt) {
		// Keep the service available: move the broken file aside and
		// start with an empty registry.
		backup := cfg.StatePath + ".corrupt-" + time.Now().Format("20060102-150405")
		if renameErr := os.Rename(cfg.StatePath, backup); renameErr != nil {
			return fmt.Errorf("opening state: %w (backup also failed: %v)", err, renameErr)
		}
		log.Warn("state file was corrupted; starting fresh", "error", err, "backup", backup)
		st, err = store.Open(cfg.StatePath, onlineWindow)
	}
	if err != nil {
		return fmt.Errorf("opening state: %w", err)
	}

	ouiPaths := append([]string{}, cfg.OUIPaths...)
	ouiPaths = append(ouiPaths, scanner.DefaultOUIPaths...)
	oui := scanner.LoadOUI(ouiPaths)
	if oui.Len() > 0 {
		log.Info("OUI vendor database loaded", "prefixes", oui.Len())
	} else {
		log.Info("no OUI database found; vendor names disabled (hint: apt install ieee-data)")
	}

	sc := scanner.New(st, oui, log, cfg.ScanInterval, cfg.ScanCIDR, cfg.ScanInterface, cfg.DisableSweep)

	dns := &dnsserver.Server{
		Addr:        cfg.DNSListen,
		Domain:      cfg.Domain,
		TTL:         cfg.TTL,
		Upstreams:   cfg.Upstreams,
		SingleLabel: cfg.AnswerSingleLabel,
		Resolver:    st,
		Log:         log,
	}
	if err := dns.Start(); err != nil {
		return fmt.Errorf(
			"DNS server failed to listen on %q: %w (hint: on Ubuntu, systemd-resolved often occupies port 53 — see README「ポート53を空ける」)",
			cfg.DNSListen, err)
	}

	webSrv := &web.Server{
		Store:   st,
		Scanner: sc,
		Info: web.Info{
			Version:      version,
			Domain:       cfg.Domain,
			DNSListen:    cfg.DNSListen,
			TTL:          cfg.TTL,
			ScanInterval: cfg.ScanInterval,
			Upstreams:    cfg.Upstreams,
		},
		Username: cfg.WebUsername,
		Password: cfg.WebPassword,
		Log:      log,
	}
	httpSrv := &http.Server{
		Addr:              cfg.WebListen,
		Handler:           webSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("web server: %w", err)
		}
	}()
	go sc.Run(ctx)
	go func() {
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := st.SaveIfDirty(); err != nil {
					log.Error("periodic state save failed", "error", err)
				}
			}
		}
	}()

	log.Info("local-dns started",
		"version", version,
		"dns", cfg.DNSListen,
		"web", cfg.WebListen,
		"domain", cfg.Domain,
		"scan_interval", cfg.ScanInterval.String(),
		"upstreams", fmt.Sprintf("%v", cfg.Upstreams),
	)

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down (signal received)")
	case runErr = <-errCh:
	}
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx) //nolint:errcheck
	dns.Shutdown(shutdownCtx)
	if err := st.SaveIfDirty(); err != nil {
		log.Error("final state save failed", "error", err)
	}
	return runErr
}
