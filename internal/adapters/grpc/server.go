// Package grpc is the inbound gRPC adapter for the idp-authentik plugin.
package grpc

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/kleffio/idp-authentik/internal/core/application"
	"github.com/kleffio/idp-authentik/internal/core/domain"
	pluginsv1 "github.com/kleffio/plugin-sdk-go/v1"
)

// Server implements all pluginsv1 server interfaces declared by this plugin.
type Server struct {
	pluginsv1.UnimplementedIdentityProviderServer
	pluginsv1.UnimplementedIdentityFrameworkServer
	pluginsv1.UnimplementedPluginHealthServer
	pluginsv1.UnimplementedUIManifestServiceServer
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
		Status:  pluginsv1.HealthResponse_HEALTHY,
		Message: "Authentik plugin running",
	}, nil
}

func (s *Server) GetCapabilities(_ context.Context, _ *pluginsv1.GetCapabilitiesRequest) (*pluginsv1.GetCapabilitiesResponse, error) {
	return &pluginsv1.GetCapabilitiesResponse{
		Capabilities: []string{
			pluginsv1.CapabilityIdentityProvider,
			pluginsv1.CapabilityIdentityFramework,
			pluginsv1.CapabilityUIManifest,
		},
	}, nil
}

// ── IdentityProvider ──────────────────────────────────────────────────────────

func (s *Server) Login(ctx context.Context, req *pluginsv1.LoginRequest) (*pluginsv1.LoginResponse, error) {
	tok, err := s.svc.Login(ctx, req.Username, req.Password)
	if err != nil {
		return &pluginsv1.LoginResponse{
			Result: &pluginsv1.LoginResponse_Error{Error: toProtoError(err)},
		}, nil
	}
	return &pluginsv1.LoginResponse{
		Result: &pluginsv1.LoginResponse_Token{Token: toTokenSet(tok)},
	}, nil
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
		return &pluginsv1.RegisterResponse{
			Result: &pluginsv1.RegisterResponse_Error{Error: toProtoError(err)},
		}, nil
	}
	return &pluginsv1.RegisterResponse{
		Result: &pluginsv1.RegisterResponse_UserId{UserId: userID},
	}, nil
}

func (s *Server) GetUser(_ context.Context, _ *pluginsv1.GetUserRequest) (*pluginsv1.GetUserResponse, error) {
	return &pluginsv1.GetUserResponse{
		Result: &pluginsv1.GetUserResponse_Error{
			Error: &pluginsv1.Error{
				Code:    pluginsv1.Error_NOT_SUPPORTED,
				Message: "GetUser is not supported; use token claims instead",
			},
		},
	}, nil
}

func (s *Server) ValidateToken(ctx context.Context, req *pluginsv1.ValidateTokenRequest) (*pluginsv1.ValidateTokenResponse, error) {
	claims, err := s.svc.ValidateToken(ctx, req.Token)
	if err != nil {
		return &pluginsv1.ValidateTokenResponse{
			Result: &pluginsv1.ValidateTokenResponse_Error{Error: toProtoError(err)},
		}, nil
	}
	return &pluginsv1.ValidateTokenResponse{
		Result: &pluginsv1.ValidateTokenResponse_Claims{
			Claims: &pluginsv1.TokenClaims{
				Subject:  claims.Subject,
				Username: claims.Username,
				Email:    claims.Email,
				Roles:    claims.Roles,
			},
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
		Result: &pluginsv1.GetOIDCConfigResponse_Config{
			Config: &pluginsv1.OIDCConfig{
				Authority:             cfg.Authority,
				ClientId:              cfg.ClientID,
				JwksUri:               cfg.JwksURI,
				Scopes:                []string{"openid", "profile", "email"},
				AuthMode:              cfg.AuthMode,
				TokenEndpoint:         cfg.TokenEndpoint,
				InternalTokenEndpoint: cfg.InternalTokenEndpoint,
				EndSessionEndpoint:    cfg.EndSessionEndpoint,
			},
		},
	}, nil
}

func (s *Server) RefreshToken(ctx context.Context, req *pluginsv1.RefreshTokenRequest) (*pluginsv1.RefreshTokenResponse, error) {
	tok, err := s.svc.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return &pluginsv1.RefreshTokenResponse{
			Result: &pluginsv1.RefreshTokenResponse_Error{Error: toProtoError(err)},
		}, nil
	}
	return &pluginsv1.RefreshTokenResponse{
		Result: &pluginsv1.RefreshTokenResponse_Token{Token: toTokenSet(tok)},
	}, nil
}

// ── IdentityFramework ─────────────────────────────────────────────────────────

func (s *Server) EnsureAdmin(ctx context.Context, _ *pluginsv1.EnsureAdminRequest) (*pluginsv1.EnsureAdminResponse, error) {
	if err := s.svc.EnsureAdmin(ctx); err != nil {
		return &pluginsv1.EnsureAdminResponse{
			Result: &pluginsv1.EnsureAdminResponse_Error{Error: toProtoError(err)},
		}, nil
	}
	return &pluginsv1.EnsureAdminResponse{}, nil
}

func (s *Server) ChangePassword(ctx context.Context, req *pluginsv1.ChangePasswordRequest) (*pluginsv1.ChangePasswordResponse, error) {
	if err := s.svc.ChangePassword(ctx, req.UserId, req.CurrentPassword, req.NewPassword); err != nil {
		return &pluginsv1.ChangePasswordResponse{
			Result: &pluginsv1.ChangePasswordResponse_Error{Error: toProtoError(err)},
		}, nil
	}
	return &pluginsv1.ChangePasswordResponse{
		Result: &pluginsv1.ChangePasswordResponse_Ok{Ok: true},
	}, nil
}

func (s *Server) ListSessions(ctx context.Context, req *pluginsv1.ListSessionsRequest) (*pluginsv1.ListSessionsResponse, error) {
	sessions, err := s.svc.ListSessions(ctx, req.UserId)
	if err != nil {
		return &pluginsv1.ListSessionsResponse{
			Result: &pluginsv1.ListSessionsResponse_Error{Error: toProtoError(err)},
		}, nil
	}
	items := make([]*pluginsv1.Session, len(sessions))
	for i, sess := range sessions {
		items[i] = &pluginsv1.Session{
			Id:         sess.ID,
			IpAddress:  sess.IPAddress,
			UserAgent:  sess.Browser,
			CreatedAt:  sess.Started,
			LastAccess: sess.LastSeen,
			Current:    sess.ID == req.CurrentSessionId,
		}
	}
	return &pluginsv1.ListSessionsResponse{
		Result: &pluginsv1.ListSessionsResponse_Sessions{
			Sessions: &pluginsv1.SessionList{Items: items},
		},
	}, nil
}

func (s *Server) RevokeSession(ctx context.Context, req *pluginsv1.RevokeSessionRequest) (*pluginsv1.RevokeSessionResponse, error) {
	if err := s.svc.RevokeSession(ctx, req.UserId, req.SessionId); err != nil {
		return &pluginsv1.RevokeSessionResponse{
			Result: &pluginsv1.RevokeSessionResponse_Error{Error: toProtoError(err)},
		}, nil
	}
	return &pluginsv1.RevokeSessionResponse{
		Result: &pluginsv1.RevokeSessionResponse_Ok{Ok: true},
	}, nil
}

// ── UIManifestService ─────────────────────────────────────────────────────────

func (s *Server) GetUIManifest(_ context.Context, _ *pluginsv1.GetUIManifestRequest) (*pluginsv1.GetUIManifestResponse, error) {
	adminURL := strings.TrimRight(s.publicURL, "/") + "/if/admin/"
	return &pluginsv1.GetUIManifestResponse{
		Result: &pluginsv1.GetUIManifestResponse_Manifest{
			Manifest: &pluginsv1.UIManifest{
				SettingsPages: []*pluginsv1.SettingsPage{
					{
						Label:     "Identity Provider",
						Href:      "/settings/identity",
						IframeUrl: fmt.Sprintf("%s#/core/applications", adminURL),
					},
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
		IdToken:      t.IDToken,
		TokenType:    t.TokenType,
		ExpiresIn:    t.ExpiresIn,
		Scope:        t.Scope,
	}
}

func toProtoError(err error) *pluginsv1.Error {
	switch {
	case domain.IsUnauthorized(err):
		return &pluginsv1.Error{Code: pluginsv1.Error_UNAUTHORIZED, Message: err.Error()}
	case domain.IsConflict(err):
		return &pluginsv1.Error{Code: pluginsv1.Error_CONFLICT, Message: err.Error()}
	default:
		return &pluginsv1.Error{Code: pluginsv1.Error_INTERNAL, Message: err.Error()}
	}
}
