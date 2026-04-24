package ports

import (
	"context"

	"github.com/kleffio/idp-authentik/internal/core/domain"
)

// IDPProvider is the outbound port through which the application talks to Authentik.
type IDPProvider interface {
	// EnsureSetup waits for Authentik to be reachable, then creates the kleff
	// OAuth2 application and client if they do not already exist. Idempotent.
	EnsureSetup(ctx context.Context) error

	// Login authenticates a user via the Resource Owner Password Credentials grant.
	// Returns ErrUnauthorized for bad credentials.
	Login(ctx context.Context, username, password string) (*domain.TokenSet, error)

	// Register creates a new user account in Authentik.
	// Returns ErrConflict if the username/email already exists.
	Register(ctx context.Context, req domain.RegisterRequest) (string, error)

	// ValidateToken verifies a raw JWT and returns its claims.
	// Returns ErrUnauthorized if the token is invalid or expired.
	ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error)

	// OIDCConfig returns the static OIDC discovery parameters for this provider.
	OIDCConfig() domain.OIDCConfig

	// RefreshToken exchanges a refresh token for a new token set.
	// Returns ErrUnauthorized if the refresh token is invalid or expired.
	RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenSet, error)

	// EnsureAdmin seeds the initial admin user and grants them the "admin" group.
	// Safe to call multiple times (idempotent).
	EnsureAdmin(ctx context.Context) error
	// ChangePassword verifies currentPassword for userID then sets newPassword.
	// Returns ErrUnauthorized if currentPassword is wrong.
	ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error

	ListSessions(ctx context.Context, userID string) ([]*domain.Session, error)
	RevokeSession(ctx context.Context, userID, sessionID string) error
}