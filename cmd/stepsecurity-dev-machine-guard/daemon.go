package main

import (
	"context"
	"errors"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
)

// runDaemon is the entrypoint for `dmg daemon`, the long-running variant of
// `send-telemetry` invoked by the systemd user service installed via
// `install --long-running`. It runs telemetry once at startup so the dashboard
// gets fresh data immediately, then loops on `config.ScanFrequencyHours`.
//
// Errors from individual telemetry runs are logged but do not exit the loop —
// systemd would just restart us, multiplying the same upstream failure into a
// retry storm. Hard exit is reserved for unrecoverable setup problems.
func runDaemon(exec executor.Executor, log *progress.Logger, cfg *cli.Config) error {
	hours, _ := strconv.Atoi(config.ScanFrequencyHours)
	if hours <= 0 {
		hours = 4
	}
	interval := time.Duration(hours) * time.Hour

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Progress("daemon starting (interval=%s)", interval)

	// Initial run.
	if err := runOnce(ctx, exec, log, cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Progress("daemon stopped during initial telemetry run")
			return nil
		}
		log.Error("initial telemetry failed: %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Progress("daemon received signal; exiting")
			return nil
		case <-ticker.C:
			if err := runOnce(ctx, exec, log, cfg); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
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
