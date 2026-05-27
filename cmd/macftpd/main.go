package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"macftpd/internal/activity"
	"macftpd/internal/auth"
	"macftpd/internal/cloudflare"
	"macftpd/internal/config"
	"macftpd/internal/ftpserver"
	"macftpd/internal/httpapi"
	"macftpd/internal/share"
	"macftpd/internal/status"
	"macftpd/internal/storage"
)

func main() {
	var configPath string
	var printConfig bool
	flag.StringVar(&configPath, "config", "", "path to macftpd JSON config")
	flag.BoolVar(&printConfig, "print-config", false, "print normalized config and exit")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if printConfig {
		fmt.Printf("%+v\n", cfg)
		return
	}
	if err := config.EnsureDirs(cfg); err != nil {
		log.Fatalf("prepare directories: %v", err)
	}
	store, err := auth.Open(cfg.Auth.UsersPath)
	if err != nil {
		log.Fatalf("open auth store: %v", err)
	}
	if err := store.BootstrapAdmin(cfg.Auth.BootstrapAdminUser, cfg.Auth.BootstrapAdminPass); err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}
	root, err := storage.New(cfg.Storage.Root, cfg.Storage.PublicDir, cfg.Storage.DropboxDir, cfg.Storage.Ignore)
	if err != nil {
		log.Fatalf("open storage root: %v", err)
	}
	activityLog, err := activity.NewFile(2000, filepath.Join(filepath.Dir(cfg.Auth.UsersPath), "activity.jsonl"))
	if err != nil {
		log.Fatalf("open activity log: %v", err)
	}
	linkStore, err := share.Open(filepath.Join(filepath.Dir(cfg.Auth.UsersPath), "shares.json"))
	if err != nil {
		log.Fatalf("open share store: %v", err)
	}
	tracker := status.New()
	ftp, err := ftpserver.New(cfg.FTP, store, root, activityLog, tracker)
	if err != nil {
		log.Fatalf("create ftp server: %v", err)
	}
	http := httpapi.New(cfg.HTTP, store, root, cloudflare.New(cfg.Cloudflare), activityLog, linkStore, tracker)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 2)
	go func() { errs <- ftp.ListenAndServe(ctx) }()
	go func() { errs <- http.ListenAndServe(ctx) }()

	if err := <-errs; err != nil {
		stop()
		log.Fatalf("server stopped: %v", err)
	}
}
