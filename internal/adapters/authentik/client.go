// Package authentik is the outbound adapter that implements ports.IDPProvider
// by talking to Authentik over its REST API and OIDC token endpoints.
package authentik

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kleffio/idp-authentik/internal/core/domain"
)

// Config holds Authentik connection parameters loaded from env vars.
type Config struct {
	BaseURL        string // internal URL, e.g. "http://authentik-server:9000"
	PublicURL      string // browser-reachable URL, e.g. "http://localhost:9000"
	BootstrapToken string // AUTHENTIK_BOOTSTRAP_TOKEN — used to call the REST API
	AppSlug        string // application slug in Authentik, default "kleff"
	AdminEmail     string // email of the initial Kleff admin user
	AdminPassword  string // password of the initial Kleff admin user
	AuthMode       string // "headless" (default) or "redirect"
}

// cachedEndpoints are discovered after EnsureSetup completes.
type cachedEndpoints struct {
	tokenEndpoint string
	jwksURI       string
	issuerURL     string
	clientID      string
}

// Client implements ports.IDPProvider for Authentik.
type Client struct {
	cfg  Config
	http *http.Client

	mu       sync.RWMutex
	ep       cachedEndpoints
	epReady  bool
}

// New creates a Client. Call EnsureSetup before performing auth operations.
func New(cfg Config) *Client {
	if cfg.AppSlug == "" {
		cfg.AppSlug = "kleff"
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = "headless"
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// ── EnsureSetup ───────────────────────────────────────────────────────────────

// EnsureSetup waits for Authentik to be reachable, then idempotently creates
// the kleff OAuth2 provider + application and caches the OIDC endpoints.
func (c *Client) EnsureSetup(ctx context.Context) error {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	tok := c.cfg.BootstrapToken

	// 1. Wait until the Authentik API is up.
	if err := c.waitReady(ctx, base, tok); err != nil {
		return err
	}

	// 2. Find the flow PKs we need.
	authFlowPK, err := c.findFlowPK(ctx, base, tok, "default-authentication-flow")
	if err != nil {
		return fmt.Errorf("find auth flow: %w", err)
	}
	authzFlowPK, err := c.findFlowPK(ctx, base, tok, "default-provider-authorization-implicit-consent")
	if err != nil {
		return fmt.Errorf("find authz flow: %w", err)
	}
	invalidationFlowPK, err := c.findFlowPK(ctx, base, tok, "default-provider-invalidation-flow")
	if err != nil {
		return fmt.Errorf("find invalidation flow: %w", err)
	}

	// 3. Find scope property mapping PKs (openid, email, profile).
	scopePKs, err := c.findScopePKs(ctx, base, tok)
	if err != nil {
		return fmt.Errorf("find scope mappings: %w", err)
	}

	// 4. Find an RSA signing certificate (needed for RS256 access-token signing).
	certPK, err := c.findSigningCert(ctx, base, tok)
	if err != nil {
		return fmt.Errorf("find signing cert: %w", err)
	}

	// 5. Create or update the OAuth2 provider, always ensuring RS256 signing.
	providerPK, err := c.ensureProvider(ctx, base, tok, authFlowPK, authzFlowPK, invalidationFlowPK, scopePKs, certPK)
	if err != nil {
		return fmt.Errorf("ensure provider: %w", err)
	}

	// 6. Create or update the application.
	if err := c.ensureApplication(ctx, base, tok, providerPK, authzFlowPK); err != nil {
		return fmt.Errorf("ensure application: %w", err)
	}

	// 7. Create a headless auth flow (no MFA) used by the headless Login() path.
	// Authentik 2025.2 removed real-password ROPC support; the flow executor is the
	// correct way to authenticate headlessly.
	if err := c.ensureHeadlessFlow(ctx, base, tok); err != nil {
		return fmt.Errorf("ensure headless flow: %w", err)
	}

	// 8. Fetch OIDC discovery document to get the canonical endpoints.
	if err := c.discoverEndpoints(ctx, base); err != nil {
		return fmt.Errorf("discover endpoints: %w", err)
	}

	// 9. Seed the admin user and "admin" group.
	if err := c.EnsureAdmin(ctx); err != nil {
		// Non-fatal — log and continue.
		fmt.Printf("authentik: warning: EnsureAdmin: %v\n", err)
	}

	return nil
}

func (c *Client) waitReady(ctx context.Context, base, tok string) error {
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v3/root/config/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.http.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for Authentik")
		case <-time.After(3 * time.Second):
		}
	}
}

func (c *Client) findFlowPK(ctx context.Context, base, tok, slug string) (string, error) {
	u := base + "/api/v3/flows/instances/?slug=" + url.QueryEscape(slug)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var page struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return "", err
	}
	if len(page.Results) == 0 {
		return "", fmt.Errorf("flow %q not found", slug)
	}
	return page.Results[0].PK, nil
}

func (c *Client) findScopePKs(ctx context.Context, base, tok string) ([]string, error) {
	managed := []string{
		"goauthentik.io/providers/oauth2/scope-openid",
		"goauthentik.io/providers/oauth2/scope-email",
		"goauthentik.io/providers/oauth2/scope-profile",
	}
	var pks []string
	for _, m := range managed {
		u := base + "/api/v3/propertymappings/provider/scope/?managed=" + url.QueryEscape(m)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		var page struct {
			Results []struct {
				PK string `json:"pk"`
			} `json:"results"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()
		if len(page.Results) > 0 {
			pks = append(pks, page.Results[0].PK)
		}
	}
	return pks, nil
}

func (c *Client) findSigningCert(ctx context.Context, base, tok string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v3/crypto/certificatekeypairs/?has_key=true", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	var page struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()
	if len(page.Results) == 0 {
		return "", fmt.Errorf("no signing certificate found in Authentik")
	}
	return page.Results[0].PK, nil
}

func (c *Client) ensureProvider(ctx context.Context, base, tok, authFlowPK, authzFlowPK, invalidationFlowPK string, scopePKs []string, certPK string) (int, error) {
	// Check if provider already exists.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v3/providers/oauth2/?name=kleff", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	var page struct {
		Results []struct {
			PK int `json:"pk"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		resp.Body.Close()
		return 0, err
	}
	resp.Body.Close()

	providerPayload := map[string]any{
		"name":                       "kleff",
		"client_id":                  "kleff-panel",
		"client_type":                "public",
		"authorization_flow":         authzFlowPK,
		"authentication_flow":        authFlowPK,
		"invalidation_flow":          invalidationFlowPK,
		"sub_mode":                   "user_email",
		"include_claims_in_id_token": true,
		"property_mappings":          scopePKs,
		"access_token_validity":      "hours=1",
		"refresh_token_validity":     "days=30",
		"redirect_uris": []map[string]string{
			{"matching_mode": "regex", "url": ".*"},
		},
		"signing_key": certPK,
		"jwt_alg":     "RS256",
	}

	if len(page.Results) > 0 {
		// Provider exists — PATCH to ensure RS256 signing is set.
		pk := page.Results[0].PK
		patchPayload, _ := json.Marshal(map[string]any{
			"signing_key": certPK,
			"jwt_alg":     "RS256",
		})
		patchReq, _ := http.NewRequestWithContext(ctx, http.MethodPatch,
			fmt.Sprintf("%s/api/v3/providers/oauth2/%d/", base, pk),
			strings.NewReader(string(patchPayload)))
		patchReq.Header.Set("Authorization", "Bearer "+tok)
		patchReq.Header.Set("Content-Type", "application/json")
		patchResp, err := c.http.Do(patchReq)
		if err != nil {
			return 0, fmt.Errorf("patch provider RS256: %w", err)
		}
		b, _ := io.ReadAll(patchResp.Body)
		patchResp.Body.Close()
		if patchResp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("patch provider RS256: status %d: %s", patchResp.StatusCode, string(b))
		}
		return pk, nil
	}

	// Create the provider.
	payload, _ := json.Marshal(providerPayload)
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v3/providers/oauth2/",
		strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("create provider: status %d: %s", resp.StatusCode, string(b))
	}
	var created struct {
		PK int `json:"pk"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return 0, err
	}
	return created.PK, nil
}

func (c *Client) ensureApplication(ctx context.Context, base, tok string, providerPK int, authzFlowPK string) error {
	// Check if application already exists.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v3/core/applications/?slug="+c.cfg.AppSlug, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	var page struct {
		Results []struct {
			Slug string `json:"slug"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		resp.Body.Close()
		return err
	}
	resp.Body.Close()
	if len(page.Results) > 0 {
		return nil // already exists
	}

	// Create the application.
	payload, _ := json.Marshal(map[string]any{
		"name":               "Kleff",
		"slug":               c.cfg.AppSlug,
		"provider":           providerPK,
		"open_in_new_tab":    false,
		"policy_engine_mode": "any",
	})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v3/core/applications/",
		strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create application: status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) discoverEndpoints(ctx context.Context, base string) error {
	issuerURL := fmt.Sprintf("%s/application/o/%s/", base, c.cfg.AppSlug)
	discoveryURL := issuerURL + ".well-known/openid-configuration"

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC discovery: status %d", resp.StatusCode)
	}
	var doc struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		JwksURI       string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}

	// Build public-facing issuer URL (browser-reachable).
	publicBase := strings.TrimRight(c.cfg.PublicURL, "/")
	if publicBase == "" {
		publicBase = base
	}
	publicIssuer := fmt.Sprintf("%s/application/o/%s/", publicBase, c.cfg.AppSlug)
	publicJwks := fmt.Sprintf("%s/application/o/%s/jwks/", publicBase, c.cfg.AppSlug)

	c.mu.Lock()
	c.ep = cachedEndpoints{
		tokenEndpoint: doc.TokenEndpoint,
		jwksURI:       publicJwks,
		issuerURL:     publicIssuer,
		clientID:      "kleff-panel",
	}
	c.epReady = true
	c.mu.Unlock()
	return nil
}

// ── EnsureAdmin ───────────────────────────────────────────────────────────────

// EnsureAdmin finds or creates the "admin" group in Authentik, then finds or
// creates the bootstrap admin user and adds them to that group.
func (c *Client) EnsureAdmin(ctx context.Context) error {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	tok := c.cfg.BootstrapToken

	// 1. Find or create the "admin" group (used for Kleff role mapping).
	groupPK, err := c.ensureGroup(ctx, base, tok, "admin")
	if err != nil {
		return fmt.Errorf("ensure admin group: %w", err)
	}

	// 2. Find the bootstrap admin user by email.
	userPK, err := c.findOrCreateUser(ctx, base, tok, c.cfg.AdminEmail, c.cfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("find/create admin user: %w", err)
	}

	// 3. Add the user to the "admin" group (idempotent).
	return c.addUserToGroup(ctx, base, tok, groupPK, userPK)
}

func (c *Client) ensureGroup(ctx context.Context, base, tok, name string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v3/core/groups/?name="+url.QueryEscape(name), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	var page struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()
	if len(page.Results) > 0 {
		return page.Results[0].PK, nil
	}

	// Create the group.
	payload, _ := json.Marshal(map[string]any{"name": name, "is_superuser": false})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v3/core/groups/",
		strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create group %q: status %d: %s", name, resp.StatusCode, string(b))
	}
	var created struct {
		PK string `json:"pk"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", err
	}
	return created.PK, nil
}

func (c *Client) findOrCreateUser(ctx context.Context, base, tok, email, password string) (int, error) {
	// Search by email (username in Authentik).
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v3/core/users/?search="+url.QueryEscape(email), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	var page struct {
		Results []struct {
			PK    int    `json:"pk"`
			Email string `json:"email"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		resp.Body.Close()
		return 0, err
	}
	resp.Body.Close()
	for _, u := range page.Results {
		if u.Email == email {
			return u.PK, nil
		}
	}

	// Create the user.
	username := strings.Split(email, "@")[0]
	payload, _ := json.Marshal(map[string]any{
		"username":   username,
		"email":      email,
		"name":       "Admin",
		"is_active":  true,
		"type":       "internal",
		"attributes": map[string]any{},
	})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v3/core/users/",
		strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.http.Do(req)
	if err != nil {
		return 0, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("create user: status %d: %s", resp.StatusCode, string(body))
	}
	var created struct {
		PK int `json:"pk"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return 0, err
	}

	// Set the password.
	pwPayload, _ := json.Marshal(map[string]any{"password": password})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v3/core/users/%d/set_password/", base, created.PK),
		strings.NewReader(string(pwPayload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.http.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()

	return created.PK, nil
}

func (c *Client) addUserToGroup(ctx context.Context, base, tok, groupPK string, userPK int) error {
	payload, _ := json.Marshal(map[string]any{"pk": userPK})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v3/core/groups/%s/add_user/", base, groupPK),
		strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	// 204 = success, 400 = already member — both are fine
	return nil
}

// ── Headless flow setup ───────────────────────────────────────────────────────

// ensureHeadlessFlow idempotently creates a custom Authentik authentication flow
// for headless login. The flow has three stages:
//
//	IdentificationStage (order 10) → PasswordStage (order 20) → UserLoginStage (order 30)
//
// No MFA stage is included — Authentik 2025.2 removed real-password ROPC support
// and the flow executor is now the correct headless path.
func (c *Client) ensureHeadlessFlow(ctx context.Context, base, tok string) error {
	// Find or create the flow.
	flowPK, _ := c.findFlowPK(ctx, base, tok, "kleff-headless-auth")
	if flowPK == "" {
		var err error
		flowPK, err = c.createFlow(ctx, base, tok, "kleff-headless-auth",
			"Kleff Headless Authentication", "authentication")
		if err != nil {
			return fmt.Errorf("create flow: %w", err)
		}
	}

	// Find or create stages (idempotent).
	idPK, err := c.findOrCreateStage(ctx, base, tok, "identification",
		"kleff-identification", map[string]any{
			"user_fields":       []string{"username", "email"},
			"show_matched_user": true,
		})
	if err != nil {
		return fmt.Errorf("create identification stage: %w", err)
	}

	pwPK, err := c.findOrCreateStage(ctx, base, tok, "password",
		"kleff-password", map[string]any{
			"backends": []string{"authentik.core.auth.InbuiltBackend"},
		})
	if err != nil {
		return fmt.Errorf("create password stage: %w", err)
	}

	loginPK, err := c.findOrCreateStage(ctx, base, tok, "user_login",
		"kleff-user-login", map[string]any{})
	if err != nil {
		return fmt.Errorf("create user_login stage: %w", err)
	}

	// Ensure all bindings exist — always idempotent (duplicate bindings are rejected by Authentik).
	stages := []struct {
		pk    string
		order int
	}{
		{idPK, 10},
		{pwPK, 20},
		{loginPK, 30},
	}
	for _, s := range stages {
		if err := c.bindStageToFlow(ctx, base, tok, flowPK, s.pk, s.order); err != nil {
			return fmt.Errorf("bind stage (order %d): %w", s.order, err)
		}
	}
	return nil
}

func (c *Client) createFlow(ctx context.Context, base, tok, slug, name, designation string) (string, error) {
	payload, _ := json.Marshal(map[string]any{
		"name":        name,
		"slug":        slug,
		"designation": designation,
		"title":       name,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v3/flows/instances/", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	var created struct {
		PK string `json:"pk"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return "", err
	}
	return created.PK, nil
}

// findOrCreateStage looks up a stage by name and creates it if absent.
// stageType must be one of: "identification", "password", "user_login".
func (c *Client) findOrCreateStage(ctx context.Context, base, tok, stageType, name string, extra map[string]any) (string, error) {
	listURL := fmt.Sprintf("%s/api/v3/stages/%s/?name=%s", base, stageType, url.QueryEscape(name))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	var page struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()
	if len(page.Results) > 0 {
		return page.Results[0].PK, nil
	}

	// Create.
	payload := map[string]any{"name": name}
	for k, v := range extra {
		payload[k] = v
	}
	body, _ := json.Marshal(payload)
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v3/stages/%s/", base, stageType),
		strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.http.Do(req)
	if err != nil {
		return "", err
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create %s stage: status %d: %s", stageType, resp.StatusCode, string(respBody))
	}
	var created struct {
		PK string `json:"pk"`
	}
	if err := json.Unmarshal(respBody, &created); err != nil {
		return "", err
	}
	return created.PK, nil
}

func (c *Client) bindStageToFlow(ctx context.Context, base, tok, flowPK, stagePK string, order int) error {
	payload, _ := json.Marshal(map[string]any{
		"target":  flowPK, // Authentik uses "target" for the flow PK in FlowStageBinding
		"stage":   stagePK,
		"order":   order,
		"enabled": true,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v3/flows/bindings/", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// 201 = created; 400 with "already exists"-style error = already bound (idempotent).
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	// Treat any 400 whose body mentions the binding already existing as success.
	if resp.StatusCode == http.StatusBadRequest &&
		(strings.Contains(string(body), "already") || strings.Contains(string(body), "unique")) {
		return nil
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ── Auth operations ───────────────────────────────────────────────────────────

// Login authenticates using Authentik's flow executor API + OAuth2 authorization
// code exchange with PKCE. This replaces ROPC which was removed in Authentik 2025.2.
//
// Flow:
//  1. Drive the `kleff-headless-auth` flow (Identification → Password → UserLogin)
//     via the flow executor, carrying a session cookie jar.
//  2. Use the authenticated session to get an authorization code from the OIDC
//     authorization endpoint (with implicit consent).
//  3. Exchange the code for tokens at the token endpoint.
func (c *Client) Login(ctx context.Context, username, password string) (*domain.TokenSet, error) {
	base := strings.TrimRight(c.cfg.BaseURL, "/")

	// Per-request HTTP client: shared cookie jar.
	// Follow redirects within the flow executor (each POST → 302 → GET → JSON),
	// but stop at the authorization endpoint redirect so we can capture the code.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			// Follow redirects inside the flow executor, preserving Accept header.
			if strings.Contains(req.URL.Path, "/api/v3/flows/executor/") {
				req.Header.Set("Accept", "application/json")
				return nil
			}
			// Stop all other redirects (e.g. authorization endpoint → callback with code).
			return http.ErrUseLastResponse
		},
	}

	flowURL := base + "/api/v3/flows/executor/kleff-headless-auth/"

	// ── Step 1: Start flow ────────────────────────────────────────────────────
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, flowURL+"?next=%2F", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authentik login: start flow: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var stage struct {
		Component string `json:"component"`
	}
	if err := json.Unmarshal(body, &stage); err != nil {
		return nil, fmt.Errorf("authentik login: parse initial challenge: %w", err)
	}
	if stage.Component != "ak-stage-identification" {
		return nil, fmt.Errorf("authentik login: unexpected initial stage %q", stage.Component)
	}

	// ── Step 2: Submit username ───────────────────────────────────────────────
	uidBody, _ := json.Marshal(map[string]any{"uid_field": username})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, flowURL,
		strings.NewReader(string(uidBody)))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err = hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authentik login: submit username: %w", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if err := json.Unmarshal(body, &stage); err != nil {
		return nil, fmt.Errorf("authentik login: parse password stage: %w", err)
	}
	// If we got back identification stage again, the user doesn't exist.
	if stage.Component != "ak-stage-password" {
		return nil, &domain.ErrUnauthorized{Msg: "invalid username or password"}
	}

	// ── Step 3: Submit password ───────────────────────────────────────────────
	pwBody, _ := json.Marshal(map[string]any{"password": password})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, flowURL,
		strings.NewReader(string(pwBody)))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err = hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authentik login: submit password: %w", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var flowResp struct {
		Component string `json:"component"`
		To        string `json:"to"`
	}
	if err := json.Unmarshal(body, &flowResp); err != nil {
		return nil, fmt.Errorf("authentik login: parse flow response: %w", err)
	}
	// Back on the password stage → wrong password.
	if flowResp.Component == "ak-stage-password" {
		return nil, &domain.ErrUnauthorized{Msg: "invalid username or password"}
	}
	if flowResp.Component != "xak-flow-redirect" {
		return nil, fmt.Errorf("authentik login: unexpected stage after password: %q", flowResp.Component)
	}
	// Session cookie is now set in jar — the user is logged in.

	// ── Step 4: Authorization code request (PKCE) ─────────────────────────────
	codeVerifier := generateCodeVerifier()
	codeChallenge := computeCodeChallenge(codeVerifier)
	state := randomHex(8)
	nonce := randomHex(8)
	redirectURI := "http://localhost/callback"

	authURL := fmt.Sprintf(
		"%s/application/o/authorize/?client_id=%s&response_type=code&scope=%s&redirect_uri=%s&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=S256",
		base,
		url.QueryEscape("kleff-panel"),
		url.QueryEscape("openid profile email"),
		url.QueryEscape(redirectURI),
		state, nonce,
		codeChallenge,
	)
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	resp, err = hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authentik login: authorization request: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("authentik login: expected auth redirect, got status %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("authentik login: parse redirect URL: %w", err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("authentik login: no auth code in redirect: %s", location)
	}

	// ── Step 5: Token exchange ────────────────────────────────────────────────
	c.mu.RLock()
	ep := c.ep
	c.mu.RUnlock()

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {ep.clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, ep.tokenEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("authentik login: token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authentik login: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)

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
		return nil, fmt.Errorf("authentik login: parse token response: %w", err)
	}
	if tok.Error != "" {
		if tok.Error == "invalid_grant" {
			return nil, &domain.ErrUnauthorized{Msg: "invalid username or password"}
		}
		return nil, fmt.Errorf("authentik login: token error: %s: %s", tok.Error, tok.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentik login: unexpected token status %d: %s", resp.StatusCode, string(body))
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

// ── PKCE helpers ──────────────────────────────────────────────────────────────

func generateCodeVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func computeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Register creates a new user in Authentik via the REST API.
func (c *Client) Register(ctx context.Context, req domain.RegisterRequest) (string, error) {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	tok := c.cfg.BootstrapToken

	payload, _ := json.Marshal(map[string]any{
		"username":   req.Username,
		"email":      req.Email,
		"name":       strings.TrimSpace(req.FirstName + " " + req.LastName),
		"is_active":  true,
		"type":       "internal",
		"attributes": map[string]any{},
	})
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v3/core/users/",
		strings.NewReader(string(payload)))
	httpReq.Header.Set("Authorization", "Bearer "+tok)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("authentik register: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest {
		// Authentik returns 400 with detail if the username/email is taken.
		return "", &domain.ErrConflict{Msg: "user already exists"}
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("authentik register: status %d: %s", resp.StatusCode, string(body))
	}

	var created struct {
		PK int `json:"pk"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return "", err
	}

	// Set the password.
	pwPayload, _ := json.Marshal(map[string]any{"password": req.Password})
	pwReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v3/core/users/%d/set_password/", base, created.PK),
		strings.NewReader(string(pwPayload)))
	pwReq.Header.Set("Authorization", "Bearer "+tok)
	pwReq.Header.Set("Content-Type", "application/json")
	pwResp, err := c.http.Do(pwReq)
	if err != nil {
		return "", fmt.Errorf("authentik register: set password: %w", err)
	}
	pwResp.Body.Close()

	return fmt.Sprintf("%d", created.PK), nil
}

// RefreshToken exchanges a refresh token for a new token set.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenSet, error) {
	c.mu.RLock()
	ep := c.ep
	c.mu.RUnlock()

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {ep.clientID},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.tokenEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("authentik refresh: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authentik refresh: %w", err)
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
		return nil, fmt.Errorf("authentik refresh: parse response: %w", err)
	}
	if tok.Error != "" {
		if tok.Error == "invalid_grant" {
			return nil, &domain.ErrUnauthorized{Msg: "refresh token is invalid or expired"}
		}
		return nil, fmt.Errorf("authentik refresh: %s: %s", tok.Error, tok.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentik refresh: unexpected status %d", resp.StatusCode)
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
	c.mu.RLock()
	ep := c.ep
	c.mu.RUnlock()
	authMode := c.cfg.AuthMode
	if authMode == "" {
		authMode = "headless"
	}
	return domain.OIDCConfig{
		Authority: ep.issuerURL,
		ClientID:  ep.clientID,
		JwksURI:   ep.jwksURI,
		AuthMode:  authMode,
	}
}

// jwksURI returns the internal JWKS URI for token validation.
func (c *Client) jwksURI() string {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	return fmt.Sprintf("%s/application/o/%s/jwks/", base, c.cfg.AppSlug)
}
