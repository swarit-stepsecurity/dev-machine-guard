package main

import (
	"context"
	"errors"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/control"
	"github.com/step-security/dev-machine-guard/internal/control/handlers"
	"github.com/step-security/dev-machine-guard/internal/control/wsclient"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
)

// runDaemon is the entrypoint for `dmg daemon`, the long-running variant of
// `send-telemetry` invoked by the systemd user service installed via
// `install --long-running`.
//
// The daemon is a supervisor of two independent goroutines that share the
// same cancellation context:
//
//  1. telemetry loop — runs telemetry.Run at startup, then on the configured
//     scan_frequency_hours interval. Failures are logged but never crash
//     the loop (systemd would restart us into the same upstream failure).
//  2. WebSocket control client — opens a persistent wss:// to the configured
//     api_endpoint, dispatches incoming commands through a control.Registry
//     populated with the hooks.install / hooks.uninstall handlers, replies
//     with typed results. Reconnects with exponential backoff forever.
//
// First SIGTERM/SIGINT cancels both goroutines via the shared context;
// the function returns once both have unwound.
func runDaemon(exec executor.Executor, log *progress.Logger, cfg *cli.Config) error {
	hours, _ := strconv.Atoi(config.ScanFrequencyHours)
	if hours <= 0 {
		hours = 4
	}
	interval := time.Duration(hours) * time.Hour

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Progress("daemon starting (interval=%s)", interval)

	// Build the control-plane registry with the feature handlers we
	// want exposed to the backend. Adding a new on-demand capability
	// is one Register call here.
	registry := control.NewRegistry(nil)
	registry.Register(handlers.NewHooksInstall(exec))
	registry.Register(handlers.NewHooksUninstall(exec))

	// Resolve the device identity once at startup. SerialNumber is the
	// same string telemetry already uses; we never re-resolve it inside
	// the daemon's lifetime.
	dev := device.Gather(ctx, exec)

	var wg sync.WaitGroup

	// Telemetry loop — always runs; this is the existing behavior.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runTelemetryLoop(ctx, exec, log, cfg, interval)
	}()

	// WS control client — only runs when ws_endpoint is configured.
	// Empty value means the operator hasn't enrolled this device into
	// the control plane yet, in which case we silently stay in
	// telemetry-only mode.
	if config.WSEndpoint != "" {
		wsCfg := wsclient.Config{
			Identity: wsclient.Identity{
				DeviceID:   dev.SerialNumber,
				CustomerID: config.CustomerID,
				WSEndpoint: config.WSEndpoint,
				APIKey:     config.APIKey,
				Platform:   dev.Platform,
			},
			Registry: registry,
			Logger:   log,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := wsclient.Run(ctx, wsCfg); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("control: wsclient.Run returned: %v", err)
			}
		}()
	} else {
		log.Progress("control plane disabled (ws_endpoint not configured)")
	}

	wg.Wait()
	log.Progress("daemon exited")
	return nil
}

// runTelemetryLoop is the inner loop of the telemetry goroutine. Same
// shape as before the WS client landed; pulled into its own function so
// runDaemon stays focused on orchestration.
func runTelemetryLoop(ctx context.Context, exec executor.Executor, log *progress.Logger, cfg *cli.Config, interval time.Duration) {
	// Initial run.
	if err := runOnce(ctx, exec, log, cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Progress("daemon stopped during initial telemetry run")
			return
		}
		log.Error("initial telemetry failed: %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Progress("telemetry loop received signal; exiting")
			return
		case <-ticker.C:
			if err := runOnce(ctx, exec, log, cfg); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Error("telemetry cycle failed: %v", err)
			}
		}
	}
}

// runOnce wraps telemetry.Run so a panic in a single cycle doesn't tear down
// the daemon. telemetry.Run honors the lock file, so concurrent cycles (e.g.
// from a second `dmg send-telemetry` invocation) fail fast on the lock.
func runOnce(ctx context.Context, exec executor.Executor, log *progress.Logger, cfg *cli.Config) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("panic in telemetry cycle: %v", r)
		}
	}()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return telemetry.Run(exec, log, cfg)
}
