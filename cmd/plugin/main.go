// Command plugin is the entrypoint for the idp-authentik Kleff plugin.
// It wires the hexagonal layers together and starts the gRPC server.
// All Authentik setup (realm, client, admin user) is performed automatically —
// no manual configuration is required.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pluginsv1 "github.com/kleffio/plugin-sdk-go/v1"
	authentikadapter "github.com/kleffio/idp-authentik/internal/adapters/authentik"
	grpcadapter "github.com/kleffio/idp-authentik/internal/adapters/grpc"
	"github.com/kleffio/idp-authentik/internal/core/application"
	"google.golang.org/grpc"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// ── Infrastructure (outbound adapter) ─────────────────────────────────────
	provider := authentikadapter.New(authentikadapter.Config{
		BaseURL:        env("AUTHENTIK_URL", "http://authentik-server:9000"),
		PublicURL:      env("AUTHENTIK_PUBLIC_URL", "http://localhost:9000"),
		BootstrapToken: env("AUTHENTIK_BOOTSTRAP_TOKEN", ""),
		AppSlug:        env("AUTHENTIK_APP_SLUG", "kleff"),
		AdminEmail:     env("AUTHENTIK_ADMIN_EMAIL", "admin@localhost"),
		AdminPassword:  env("AUTHENTIK_ADMIN_PASSWORD", "admin"),
		AuthMode:       "headless",
	})

	// ── Application layer ──────────────────────────────────────────────────────
	svc := application.New(provider)

	// ── Inbound adapter (gRPC) ─────────────────────────────────────────────────
	srv := grpcadapter.New(svc,
		env("AUTHENTIK_PUBLIC_URL", "http://localhost:9000"),
		env("AUTHENTIK_APP_SLUG", "kleff"),
	)

	gs := grpc.NewServer()
	pluginsv1.RegisterIdentityPluginServer(gs, srv)
	pluginsv1.RegisterPluginHealthServer(gs, srv)
	pluginsv1.RegisterPluginUIServer(gs, srv)

	port := env("PLUGIN_PORT", "50051")
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}

	// Start gRPC immediately so the platform can dial while setup is in progress.
	go func() {
		logger.Info("plugin listening", "port", port)
		if err := gs.Serve(lis); err != nil {
			logger.Error("gRPC server error", "error", err)
			os.Exit(1)
		}
	}()

	// ── Auto-configure Authentik in the background ─────────────────────────────
	// Retries indefinitely — the Authentik companion containers take time to
	// start, and this is safe to call multiple times (idempotent).
	// srv.SetReady() is called once setup succeeds so GetOIDCConfig starts
	// returning a valid config and the platform's ready check fires.
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := provider.EnsureSetup(ctx)
			cancel()
			if err == nil {
				logger.Info("Authentik configured",
					"base", env("AUTHENTIK_URL", "http://authentik-server:9000"),
					"app", env("AUTHENTIK_APP_SLUG", "kleff"),
				)
				srv.SetReady()
				return
			}
			logger.Warn("waiting for Authentik...", "error", err)
			time.Sleep(5 * time.Second)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	logger.Info("shutting down")
	gs.GracefulStop()
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
