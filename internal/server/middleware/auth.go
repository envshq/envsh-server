package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/envshq/envsh-server/internal/auth"
	"github.com/envshq/envsh-server/internal/server/response"
)

type contextKey string

const (
	// HumanClaimsKey is the context key for human JWT claims.
	HumanClaimsKey contextKey = "human_claims"
	// MachineClaimsKey is the context key for machine JWT claims.
	MachineClaimsKey contextKey = "machine_claims"
)

// RequireHuman validates a human JWT and injects HumanClaims into context.
// It also checks the JTI revocation list so that explicitly revoked tokens are
// rejected immediately rather than waiting for natural expiry.
func RequireHuman(jwtSvc *auth.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				response.Unauthorized(w, "missing authorization header")
				return
			}
			claims, err := jwtSvc.VerifyHumanToken(token)
			if err != nil {
				response.Unauthorized(w, "invalid or expired token")
				return
			}
			// Check JTI revocation list.
			revoked, err := jwtSvc.CheckJTIRevoked(r.Context(), claims.ID)
			if err != nil || revoked {
				response.Unauthorized(w, "invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), HumanClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireMachine validates a machine JWT and injects MachineClaims into context.
// It also checks the JTI revocation list so that revoked machine tokens are
// rejected immediately.
func RequireMachine(jwtSvc *auth.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				response.Unauthorized(w, "missing authorization header")
				return
			}
			claims, err := jwtSvc.VerifyMachineToken(token)
			if err != nil {
				response.Unauthorized(w, "invalid or expired token")
				return
			}
			// Check JTI revocation list.
			revoked, err := jwtSvc.CheckJTIRevoked(r.Context(), claims.ID)
			if err != nil || revoked {
				response.Unauthorized(w, "invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), MachineClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireHumanOrMachine accepts either human or machine JWT.
// It checks the JTI revocation list for whichever token type is presented.
func RequireHumanOrMachine(jwtSvc *auth.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				response.Unauthorized(w, "missing authorization header")
				return
			}
			// Try human first
			if humanClaims, err := jwtSvc.VerifyHumanToken(token); err == nil {
				revoked, err := jwtSvc.CheckJTIRevoked(r.Context(), humanClaims.ID)
				if err != nil || revoked {
					response.Unauthorized(w, "invalid or expired token")
					return
				}
				ctx := context.WithValue(r.Context(), HumanClaimsKey, humanClaims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// Try machine
			if machineClaims, err := jwtSvc.VerifyMachineToken(token); err == nil {
				revoked, err := jwtSvc.CheckJTIRevoked(r.Context(), machineClaims.ID)
				if err != nil || revoked {
					response.Unauthorized(w, "invalid or expired token")
					return
				}
				ctx := context.WithValue(r.Context(), MachineClaimsKey, machineClaims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			response.Unauthorized(w, "invalid or expired token")
		})
	}
}

// RequireNotRevoked checks that the human user hasn't been removed from their workspace.
// Must be stacked after RequireHuman or RequireHumanOrMachine.
// User-level routes (workspace list/switch) should NOT use this middleware.
func RequireNotRevoked(jwtSvc *auth.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if claims := HumanClaimsFrom(r.Context()); claims != nil {
				revoked, err := jwtSvc.IsMemberRevoked(r.Context(), claims.WorkspaceID.String(), claims.Subject)
				if err != nil || revoked {
					response.Unauthorized(w, "access revoked")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HumanClaimsFrom extracts HumanClaims from context. Returns nil if not present.
func HumanClaimsFrom(ctx context.Context) *auth.HumanClaims {
	v, _ := ctx.Value(HumanClaimsKey).(*auth.HumanClaims)
	return v
}

// MachineClaimsFrom extracts MachineClaims from context. Returns nil if not present.
func MachineClaimsFrom(ctx context.Context) *auth.MachineClaims {
	v, _ := ctx.Value(MachineClaimsKey).(*auth.MachineClaims)
	return v
}

func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}
