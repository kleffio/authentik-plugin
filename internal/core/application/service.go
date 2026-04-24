package application

import (
	"context"

	"github.com/kleffio/idp-authentik/internal/core/domain"
	"github.com/kleffio/idp-authentik/internal/core/ports"
)

// Service is the use-case coordinator for the Authentik IDP plugin.
type Service struct {
	provider ports.IDPProvider
}

// New creates a Service backed by the given IDPProvider.
func New(provider ports.IDPProvider) *Service {
	return &Service{provider: provider}
}

func (s *Service) Login(ctx context.Context, username, password string) (*domain.TokenSet, error) {
	return s.provider.Login(ctx, username, password)
}

func (s *Service) Register(ctx context.Context, req domain.RegisterRequest) (string, error) {
	return s.provider.Register(ctx, req)
}

func (s *Service) ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error) {
	return s.provider.ValidateToken(ctx, rawToken)
}

func (s *Service) OIDCConfig() domain.OIDCConfig {
	return s.provider.OIDCConfig()
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenSet, error) {
	return s.provider.RefreshToken(ctx, refreshToken)
}

func (s *Service) EnsureAdmin(ctx context.Context) error {
	return s.provider.EnsureAdmin(ctx)
}

func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	return s.provider.ChangePassword(ctx, userID, currentPassword, newPassword)
}

func (s *Service) ListSessions(ctx context.Context, userID string) ([]*domain.Session, error) {
	return s.provider.ListSessions(ctx, userID)
}

func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	return s.provider.RevokeSession(ctx, userID, sessionID)
}
