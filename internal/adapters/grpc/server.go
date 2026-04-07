// Package grpc is the inbound gRPC adapter for the idp-authentik plugin.
package grpc

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	pluginsv1 "github.com/kleffio/plugin-sdk-go/v1"
	"github.com/kleffio/idp-authentik/internal/core/application"
	"github.com/kleffio/idp-authentik/internal/core/domain"
)

// Server implements all pluginsv1 server interfaces declared by this plugin.
type Server struct {
	pluginsv1.UnimplementedIdentityPluginServer
	pluginsv1.UnimplementedPluginHealthServer
	pluginsv1.UnimplementedPluginUIServer
	svc       *application.Service
	publicURL string // browser-reachable Authentik URL (for UI manifest)
	appSlug   string
	setupDone atomic.Bool // true once EnsureSetup has completed successfully
}

// New creates a Server backed by the given application Service.
func New(svc *application.Service, publicURL, appSlug string) *Server {
	if appSlug == "" {
		appSlug = "kleff"
	}
	return &Server{svc: svc, publicURL: publicURL, appSlug: appSlug}
}

// SetReady marks setup as complete. Called by main after EnsureSetup succeeds.
func (s *Server) SetReady() { s.setupDone.Store(true) }

// ── PluginHealth ──────────────────────────────────────────────────────────────

func (s *Server) Health(_ context.Context, _ *pluginsv1.HealthRequest) (*pluginsv1.HealthResponse, error) {
	return &pluginsv1.HealthResponse{
		Status:  pluginsv1.HealthStatusHealthy,
		Message: "Authentik plugin running",
	}, nil
}

func (s *Server) GetCapabilities(_ context.Context, _ *pluginsv1.GetCapabilitiesRequest) (*pluginsv1.GetCapabilitiesResponse, error) {
	return &pluginsv1.GetCapabilitiesResponse{
		Capabilities: []string{
			pluginsv1.CapabilityIdentityProvider,
			pluginsv1.CapabilityUIManifest,
		},
	}, nil
}

// ── IdentityPlugin ────────────────────────────────────────────────────────────

func (s *Server) Login(ctx context.Context, req *pluginsv1.LoginRequest) (*pluginsv1.LoginResponse, error) {
	tok, err := s.svc.Login(ctx, req.Username, req.Password)
	if err != nil {
		return &pluginsv1.LoginResponse{Error: toPluginError(err)}, nil
	}
	return &pluginsv1.LoginResponse{Token: toTokenSet(tok)}, nil
}

func (s *Server) Register(ctx context.Context, req *pluginsv1.RegisterRequest) (*pluginsv1.RegisterResponse, error) {
	userID, err := s.svc.Register(ctx, domain.RegisterRequest{
		Username:  req.Username,
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		return &pluginsv1.RegisterResponse{Error: toPluginError(err)}, nil
	}
	return &pluginsv1.RegisterResponse{UserID: userID}, nil
}

func (s *Server) GetUser(_ context.Context, _ *pluginsv1.GetUserRequest) (*pluginsv1.GetUserResponse, error) {
	return &pluginsv1.GetUserResponse{
		Error: &pluginsv1.PluginError{
			Code:    pluginsv1.ErrorCodeNotSupported,
			Message: "GetUser is not supported; use token claims instead",
		},
	}, nil
}

func (s *Server) ValidateToken(ctx context.Context, req *pluginsv1.ValidateTokenRequest) (*pluginsv1.ValidateTokenResponse, error) {
	claims, err := s.svc.ValidateToken(ctx, req.Token)
	if err != nil {
		return &pluginsv1.ValidateTokenResponse{Error: toPluginError(err)}, nil
	}
	return &pluginsv1.ValidateTokenResponse{
		Claims: &pluginsv1.TokenClaims{
			Subject: claims.Subject,
			Email:   claims.Email,
			Roles:   claims.Roles,
		},
	}, nil
}

func (s *Server) GetOIDCConfig(_ context.Context, _ *pluginsv1.GetOIDCConfigRequest) (*pluginsv1.GetOIDCConfigResponse, error) {
	// Return empty config while EnsureSetup is still running so the platform's
	// ready check stays false until Authentik is fully configured.
	if !s.setupDone.Load() {
		return &pluginsv1.GetOIDCConfigResponse{}, nil
	}
	cfg := s.svc.OIDCConfig()
	return &pluginsv1.GetOIDCConfigResponse{
		Config: &pluginsv1.OIDCConfig{
			Authority: cfg.Authority,
			ClientID:  cfg.ClientID,
			JwksURI:   cfg.JwksURI,
			Scopes:    []string{"openid", "profile", "email"},
			AuthMode:  cfg.AuthMode,
		},
	}, nil
}

func (s *Server) RefreshToken(ctx context.Context, req *pluginsv1.RefreshTokenRequest) (*pluginsv1.RefreshTokenResponse, error) {
	tok, err := s.svc.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return &pluginsv1.RefreshTokenResponse{Error: toPluginError(err)}, nil
	}
	return &pluginsv1.RefreshTokenResponse{Token: toTokenSet(tok)}, nil
}

func (s *Server) EnsureAdmin(ctx context.Context, _ *pluginsv1.EnsureAdminRequest) (*pluginsv1.EnsureAdminResponse, error) {
	if err := s.svc.EnsureAdmin(ctx); err != nil {
		return &pluginsv1.EnsureAdminResponse{Error: toPluginError(err)}, nil
	}
	return &pluginsv1.EnsureAdminResponse{}, nil
}

// ── PluginUI ──────────────────────────────────────────────────────────────────

func (s *Server) GetUIManifest(_ context.Context, _ *pluginsv1.GetUIManifestRequest) (*pluginsv1.GetUIManifestResponse, error) {
	adminURL := strings.TrimRight(s.publicURL, "/") + "/if/admin/"
	return &pluginsv1.GetUIManifestResponse{
		Manifest: &pluginsv1.UIManifest{
			SettingsPages: []*pluginsv1.SettingsPage{
				{
					Label:     "Identity Provider",
					Path:      "/settings/identity",
					IframeURL: fmt.Sprintf("%s#/core/applications", adminURL),
				},
			},
		},
	}, nil
}

// ── Type mapping helpers ──────────────────────────────────────────────────────

func toTokenSet(t *domain.TokenSet) *pluginsv1.TokenSet {
	return &pluginsv1.TokenSet{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		IDToken:      t.IDToken,
		TokenType:    t.TokenType,
		ExpiresIn:    t.ExpiresIn,
		Scope:        t.Scope,
	}
}

func toPluginError(err error) *pluginsv1.PluginError {
	switch {
	case domain.IsUnauthorized(err):
		return &pluginsv1.PluginError{Code: pluginsv1.ErrorCodeUnauthorized, Message: err.Error()}
	case domain.IsConflict(err):
		return &pluginsv1.PluginError{Code: pluginsv1.ErrorCodeConflict, Message: err.Error()}
	default:
		return &pluginsv1.PluginError{Code: pluginsv1.ErrorCodeInternal, Message: err.Error()}
	}
}
