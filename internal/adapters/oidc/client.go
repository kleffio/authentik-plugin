// Package oidc is the outbound adapter that implements ports.IDPProvider
// by talking to Authentik over OIDC/OAuth2.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kleffio/idp-authentik/internal/core/domain"
)

// Config holds the OIDC connection parameters loaded from env vars.
type Config struct {
	Issuer       string // e.g. "http://authentik-server:9000/application/o/kleff/"
	ClientID     string
	ClientSecret string // optional, for confidential clients
	AuthMode     string // "headless" (default) or "redirect"
}

// discovered holds the endpoints fetched from the OIDC discovery document.
type discovered struct {
	TokenEndpoint string
	JwksURI       string
}

// Client implements ports.IDPProvider for Authentik.
type Client struct {
	cfg      Config
	http     *http.Client
	endpoints discovered
}

// New creates a Client. Call Discover before use.
func New(cfg Config) *Client {
	if cfg.AuthMode == "" {
		cfg.AuthMode = "headless"
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// Discover fetches the OIDC discovery document and caches the endpoints.
func (c *Client) Discover(ctx context.Context) error {
	if c.cfg.Issuer == "" {
		return fmt.Errorf("OIDC_ISSUER not configured")
	}
	discoveryURL := strings.TrimRight(c.cfg.Issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc discovery: unexpected status %d", resp.StatusCode)
	}

	var doc struct {
		TokenEndpoint string `json:"token_endpoint"`
		JwksURI       string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("oidc discovery: decode: %w", err)
	}
	if doc.TokenEndpoint == "" || doc.JwksURI == "" {
		return fmt.Errorf("oidc discovery: missing token_endpoint or jwks_uri")
	}

	c.endpoints = discovered{
		TokenEndpoint: doc.TokenEndpoint,
		JwksURI:       doc.JwksURI,
	}
	return nil
}

// Login authenticates via the Resource Owner Password Credentials grant.
func (c *Client) Login(ctx context.Context, username, password string) (*domain.TokenSet, error) {
	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {c.cfg.ClientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid profile email"},
	}
	if c.cfg.ClientSecret != "" {
		data.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoints.TokenEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc login: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc login: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tok struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		IDToken          string `json:"id_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oidc login: parse response: %w", err)
	}
	if tok.Error != "" {
		if tok.Error == "invalid_grant" || strings.Contains(tok.ErrorDescription, "Invalid credentials") {
			return nil, &domain.ErrUnauthorized{Msg: "invalid username or password"}
		}
		return nil, fmt.Errorf("oidc login: %s: %s", tok.Error, tok.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc login: unexpected status %d", resp.StatusCode)
	}
	return &domain.TokenSet{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		TokenType:    tok.TokenType,
		ExpiresIn:    tok.ExpiresIn,
		Scope:        tok.Scope,
	}, nil
}

// RefreshToken exchanges a refresh token for a new token set.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenSet, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.cfg.ClientID},
		"refresh_token": {refreshToken},
	}
	if c.cfg.ClientSecret != "" {
		data.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoints.TokenEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc refresh: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc refresh: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tok struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		IDToken          string `json:"id_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oidc refresh: parse response: %w", err)
	}
	if tok.Error != "" {
		if tok.Error == "invalid_grant" {
			return nil, &domain.ErrUnauthorized{Msg: "refresh token is invalid or expired"}
		}
		return nil, fmt.Errorf("oidc refresh: %s: %s", tok.Error, tok.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc refresh: unexpected status %d", resp.StatusCode)
	}
	return &domain.TokenSet{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		TokenType:    tok.TokenType,
		ExpiresIn:    tok.ExpiresIn,
		Scope:        tok.Scope,
	}, nil
}

// OIDCConfig returns the discovery parameters the frontend needs.
func (c *Client) OIDCConfig() domain.OIDCConfig {
	return domain.OIDCConfig{
		Authority: strings.TrimRight(c.cfg.Issuer, "/"),
		ClientID:  c.cfg.ClientID,
		JwksURI:   c.endpoints.JwksURI,
		AuthMode:  c.cfg.AuthMode,
	}
}

// jwksURI returns the cached JWKS URI for use by the JWKS validator.
func (c *Client) jwksURI() string {
	return c.endpoints.JwksURI
}
