package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/envshq/envsh-server/internal/auth"
	"github.com/envshq/envsh-server/internal/config"
	"github.com/envshq/envsh-server/internal/server/router"
	"github.com/envshq/envsh-server/internal/store/postgres"
	redistore "github.com/envshq/envsh-server/internal/store/redis"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("loading config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Connect to Postgres
	db, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("connecting to postgres", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Connect to Redis
	redisClient, err := redistore.Connect(ctx, cfg.RedisURL)
	if err != nil {
		logger.Error("connecting to redis", "error", err)
		os.Exit(1)
	}
	defer redisClient.Close()

	// Stores
	stores := router.Stores{
		Users:      postgres.NewUserStore(db),
		Workspaces: postgres.NewWorkspaceStore(db),
		Projects:   postgres.NewProjectStore(db),
		Secrets:    postgres.NewSecretStore(db),
		Machines:   postgres.NewMachineStore(db),
		Keys:       postgres.NewKeyStore(db),
		Audit:      postgres.NewAuditLogStore(db),
	}

	// Auth services
	redisAuthStore := redistore.NewAuthStore(redisClient)
	jwtSvc := auth.NewJWTService(cfg.JWTSecret, redisAuthStore)
	var emailSender auth.EmailSender = &auth.ConsoleEmailSender{}
	emailSvc := auth.NewEmailAuthService(redisAuthStore, emailSender)
	machineSvc := auth.NewMachineAuthService(redisAuthStore, jwtSvc)

	services := router.Services{
		Email:   emailSvc,
		JWT:     jwtSvc,
		Machine: machineSvc,
	}

	// Build router
	h := router.New(stores, services, redisClient, logger)

	srv := &http.Server{
		Addr:         cfg.ServerAddr,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		logger.Info("shutting down server")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	logger.Info("server starting", "addr", cfg.ServerAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
