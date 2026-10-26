package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auditapi "github.com/MattKenyei/password-manager-backend/internal/api/audit"
	"github.com/MattKenyei/password-manager-backend/internal/api/auth"
	"github.com/MattKenyei/password-manager-backend/internal/api/devices"
	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/api/middleware"
	synchandler "github.com/MattKenyei/password-manager-backend/internal/api/sync"
	"github.com/MattKenyei/password-manager-backend/internal/audit"
	"github.com/MattKenyei/password-manager-backend/internal/config"
	"github.com/MattKenyei/password-manager-backend/internal/ratelimit"
	"github.com/MattKenyei/password-manager-backend/internal/storage"
	"github.com/MattKenyei/password-manager-backend/internal/token"
	"github.com/MattKenyei/password-manager-backend/internal/ws"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := storage.NewPostgres(ctx, cfg.Postgres.DSN())
	if err != nil {
		logger.Error("failed to connect to postgres", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	auditLogger := audit.NewLogger(pool, 1000, logger)
	logger.Info("connected to postgres")

	userRepo := storage.NewUserRepository(pool)
	deviceRepo := storage.NewDeviceRepository(pool)
	refreshRepo := storage.NewRefreshTokenRepository(pool)
	itemRepo := storage.NewItemRepository(pool)
	issuer := token.NewIssuer(cfg.JWT.Secret, cfg.JWT.AccessTTL)
	hub := ws.NewHub(logger)

	authHandler := auth.NewHandler(userRepo, deviceRepo, refreshRepo, issuer, cfg, auditLogger, logger)
	auditHandler := auditapi.NewHandler(pool, logger)
	devicesHandler := devices.NewHandler(deviceRepo, refreshRepo, logger)
	syncHandler := synchandler.NewHandler(itemRepo, hub, logger)
	wsHandler := ws.NewHandler(hub, issuer, logger)

	redisClient, err := storage.NewRedis(ctx, cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		logger.Error("failed to connect to redis", "error", err)
		os.Exit(1)
	}
	defer redisClient.Close()

	// Лимиты: 10 попыток логина в минуту, 30 регистраций в минуту с одного IP.
	loginLimiter := ratelimit.New(redisClient, 10, time.Minute)
	registerLimiter := ratelimit.New(redisClient, 30, time.Minute)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, "postgres_down", err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /auth/register", middleware.RateLimit(registerLimiter, logger, authHandler.Register))
	mux.HandleFunc("POST /auth/login/start", middleware.RateLimit(loginLimiter, logger, authHandler.LoginStart))
	mux.HandleFunc("POST /auth/login/finish", middleware.RateLimit(loginLimiter, logger, authHandler.LoginFinish))
	mux.HandleFunc("POST /auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /auth/logout", authHandler.Logout)

	mux.HandleFunc("GET /ws", wsHandler.ServeWS)
	mux.HandleFunc("GET /devices", middleware.RequireAuth(issuer, devicesHandler.List))
	mux.HandleFunc("DELETE /devices/{id}", middleware.RequireAuth(issuer, devicesHandler.Revoke))
	mux.HandleFunc("POST /sync", middleware.RequireAuth(issuer, syncHandler.Push))
	mux.HandleFunc("GET /sync", middleware.RequireAuth(issuer, syncHandler.Pull))
	mux.HandleFunc("GET /audit", middleware.RequireAuth(issuer, auditHandler.List))

	srv := &http.Server{
		Addr:         cfg.Server.Addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("server starting", "addr", cfg.Server.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received")

	hub.Shutdown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}

	auditLogger.Close()

	logger.Info("server stopped cleanly")
}
