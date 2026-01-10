package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/health"
	"probixel/pkg/watchdog"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	pidFile := flag.String("pidfile", "/tmp/probixel.pid", "Path to PID file")
	healthCheck := flag.Bool("health", false, "Perform health check and exit")
	delaySeconds := flag.Int("delay", 10, "Starting window delay in seconds (0 to disable)")
	flag.Parse()

	if *healthCheck {
		health.CheckHealth(*pidFile)
	}

	// Write PID file
	if err := health.WritePIDFile(*pidFile); err != nil {
		log.Fatalf("Failed to write PID file: %v", err)
	}
	defer func() { _ = os.Remove(*pidFile) }()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set the starting window from the delay flag
	watchdog.StartingWindow = time.Duration(*delaySeconds) * time.Second

	wd := watchdog.NewWatchdog(*configPath, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal, stopping agents...")
		wd.Stop()
		cancel()
	}()

	wd.Start(ctx)

	<-ctx.Done()
	log.Println("Agent stopped.")
}
