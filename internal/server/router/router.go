package router

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/envshq/envsh-server/internal/auth"
	"github.com/envshq/envsh-server/internal/config"
	"github.com/envshq/envsh-server/internal/server/handler"
	"github.com/envshq/envsh-server/internal/server/middleware"
	"github.com/envshq/envsh-server/internal/store"
)

// Stores groups all store dependencies.
type Stores struct {
	Users      store.UserStore
	Workspaces store.WorkspaceStore
	Projects   store.ProjectStore
	Secrets    store.SecretStore
	Machines   store.MachineStore
	Keys       store.KeyStore
	Audit      store.AuditLogStore
}

// Services groups all service dependencies.
type Services struct {
	Email   *auth.EmailAuthService
	JWT     *auth.JWTService
	Machine *auth.MachineAuthService
}

// Per-endpoint rate limit constants (requests per 60-second window).
const (
	rateLimitDefault     = 100
	rateLimitRequestCode = 5
	rateLimitVerifyCode  = 10
)

// New builds and returns the chi router with all routes registered.
func New(stores Stores, services Services, redisClient *redis.Client, logger *slog.Logger, cfg *config.Config) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.Logging(logger))

	// Default rate limit applied to all routes.
	r.Use(middleware.RateLimit(redisClient, rateLimitDefault))

	// Health endpoints (no auth)
	r.Get("/health", handler.Health)
	r.Get("/health/ready", handler.HealthReady)

	// Auth endpoints (no auth required).
	// Sensitive auth endpoints get tighter per-route rate limits applied
	// via an inline group so that the tighter middleware wraps only those routes.
	authH := handler.NewAuthHandler(
		stores.Users,
		stores.Workspaces,
		stores.Machines,
		stores.Audit,
		services.Email,
		services.JWT,
		services.Machine,
	)

	// Tight limit: 5 req/min for request-code (prevents email spam).
	r.Group(func(r chi.Router) {
		r.Use(middleware.RateLimit(redisClient, rateLimitRequestCode))
		r.Post("/auth/email-login", authH.EmailLogin)
	})

	// Tight limit: 10 req/min for verify-code (prevents brute-force).
	r.Group(func(r chi.Router) {
		r.Use(middleware.RateLimit(redisClient, rateLimitVerifyCode))
		r.Post("/auth/email-verify", authH.EmailVerify)
	})

	// Standard rate limit for remaining auth endpoints.
	r.Post("/auth/refresh", authH.Refresh)
	r.Post("/auth/logout", authH.Logout)
	r.Post("/auth/machine-challenge", authH.MachineChallenge)
	r.Post("/auth/machine-verify", authH.MachineVerify)

	requireHuman := middleware.RequireHuman(services.JWT)
	requireNotRevoked := middleware.RequireNotRevoked(services.JWT)
	requireHumanOrMachine := middleware.RequireHumanOrMachine(services.JWT)

	wsH := handler.NewWorkspaceHandler(stores.Workspaces, stores.Users, stores.Audit, services.JWT, cfg.FreeTierSeatMax)

	// User-level routes — valid JWT required, but no member revocation check.
	// A removed member must be able to list workspaces and switch away.
	r.Group(func(r chi.Router) {
		r.Use(requireHuman)
		r.Get("/workspaces", wsH.ListWorkspaces)
		r.Post("/workspaces/switch", wsH.SwitchWorkspace)
	})

	// Workspace-scoped human routes — requires active membership.
	r.Group(func(r chi.Router) {
		r.Use(requireHuman)
		r.Use(requireNotRevoked)

		r.Get("/workspace", wsH.Get)
		r.Patch("/workspace", wsH.Update)
		r.Get("/workspace/members", wsH.ListMembers)
		r.Post("/workspace/members/invite", wsH.InviteMember)
		r.Delete("/workspace/members/{userID}", wsH.RemoveMember)

		// Projects
		projH := handler.NewProjectHandler(stores.Projects, stores.Workspaces, stores.Audit)
		r.Get("/projects", projH.List)
		r.Post("/projects", projH.Create)
		r.Delete("/projects/{projectID}", projH.Delete)

		// Machines
		machineH := handler.NewMachineHandler(stores.Machines, stores.Projects, stores.Workspaces, stores.Audit)
		r.Get("/machines", machineH.List)
		r.Post("/machines", machineH.Create)
		r.Delete("/machines/{machineID}", machineH.Revoke)
		r.Get("/machines/{machineID}/key", machineH.GetKey)

		// SSH Keys
		keyH := handler.NewKeyHandler(stores.Keys, stores.Machines, stores.Audit)
		r.Get("/keys", keyH.List)
		r.Get("/keys/workspace", keyH.ListWorkspaceKeys)
		r.Post("/keys", keyH.Register)
		r.Delete("/keys/{keyID}", keyH.Revoke)

		// Audit log (admin only — enforced inside handler)
		auditH := handler.NewAuditHandler(stores.Audit, stores.Workspaces)
		r.Get("/audit", auditH.List)
	})

	// Human or machine authenticated routes — also requires active membership for humans.
	r.Group(func(r chi.Router) {
		r.Use(requireHumanOrMachine)
		r.Use(requireNotRevoked)

		secretH := handler.NewSecretHandler(
			stores.Secrets,
			stores.Projects,
			stores.Workspaces,
			stores.Audit,
		)
		r.Post("/secrets/push", secretH.Push)
		r.Get("/secrets/pull", secretH.Pull)
		r.Get("/secrets/list", secretH.List)
		r.Get("/secrets/{secretID}/recipients", secretH.GetRecipients)
	})

	return r
}
