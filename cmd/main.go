package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/health"
	"probixel/pkg/watchdog"
)

func run(ctx context.Context, configPath, pidFile string, delaySeconds int) error {
	if err := health.WritePIDFile(pidFile); err != nil {
		return fmt.Errorf("failed to write PID file: %v", err)
	}
	defer func() { _ = os.Remove(pidFile) }()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	watchdog.StartingWindow = time.Duration(delaySeconds) * time.Second

	wd := watchdog.NewWatchdog(configPath, cfg)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	go func() {
		select {
		case <-sigChan:
			log.Println("Received shutdown signal, stopping agents...")
			wd.Stop()
			cancel()
		case <-ctx.Done():
		}
	}()

	wd.Start(ctx)

	<-ctx.Done()
	log.Println("Agent stopped.")

	return nil
}

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	pidFile := flag.String("pidfile", "/tmp/probixel.pid", "Path to PID file")
	healthCheck := flag.Bool("health", false, "Perform health check and exit")
	delaySeconds := flag.Int("delay", 10, "Starting window delay in seconds (0 to disable)")
	flag.Parse()

	if *healthCheck {
		health.CheckHealth(*pidFile)
	}

	if err := run(context.Background(), *configPath, *pidFile, *delaySeconds); err != nil {
		log.Fatal(err)
	}
}
