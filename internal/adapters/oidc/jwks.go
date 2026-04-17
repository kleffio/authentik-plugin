package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kleffio/idp-authentik/internal/core/domain"
)

var (
	jwksMu   sync.RWMutex
	jwksKeys = map[string]crypto.PublicKey{}
	jwksTTL  time.Time
)

const jwksCacheDuration = 5 * time.Minute

// ValidateToken verifies a JWT (RS256 or ES256) against Authentik's JWKS endpoint.
// Keys are cached for 5 minutes; a cache miss triggers one re-fetch.
func (c *Client) ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, &domain.ErrUnauthorized{Msg: "malformed JWT"}
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, &domain.ErrUnauthorized{Msg: "invalid JWT header"}
	}

	key, err := c.getKey(ctx, header.Kid)
	if err != nil {
		return nil, &domain.ErrUnauthorized{Msg: err.Error()}
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &domain.ErrUnauthorized{Msg: "invalid JWT signature encoding"}
	}

	message := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(message))

	switch header.Alg {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, &domain.ErrUnauthorized{Msg: "key type mismatch for RS256"}
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], sigBytes); err != nil {
			return nil, &domain.ErrUnauthorized{Msg: "invalid JWT signature"}
		}
	case "ES256":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, &domain.ErrUnauthorized{Msg: "key type mismatch for ES256"}
		}
		if len(sigBytes) != 64 {
			return nil, &domain.ErrUnauthorized{Msg: "invalid ES256 signature length"}
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if !ecdsa.Verify(ecKey, digest[:], r, s) {
			return nil, &domain.ErrUnauthorized{Msg: "invalid JWT signature"}
		}
	default:
		return nil, &domain.ErrUnauthorized{Msg: fmt.Sprintf("unsupported algorithm %q", header.Alg)}
	}

	var claims struct {
		Sub               string   `json:"sub"`
		Email             string   `json:"email"`
		Exp               int64    `json:"exp"`
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Roles             []string `json:"roles"`
		// Authentik puts groups in the "groups" claim
		Groups []string `json:"groups"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, &domain.ErrUnauthorized{Msg: "invalid JWT claims"}
	}
	if claims.Sub == "" {
		return nil, &domain.ErrUnauthorized{Msg: "missing sub claim"}
	}
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, &domain.ErrUnauthorized{Msg: "token expired"}
	}

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Name
	}

	roles := append(claims.Roles, claims.Groups...)
	return &domain.TokenClaims{Subject: claims.Sub, Email: claims.Email, Roles: roles, Username: username}, nil
}

func (c *Client) getKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	jwksMu.RLock()
	key, ok := jwksKeys[kid]
	fresh := time.Now().Before(jwksTTL)
	jwksMu.RUnlock()

	if ok && fresh {
		return key, nil
	}
	if err := c.fetchJWKS(ctx); err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	jwksMu.RLock()
	key, ok = jwksKeys[kid]
	jwksMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	return key, nil
}

func (c *Client) fetchJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURI(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Crv string `json:"crv"`
			N   string `json:"n"`
			E   string `json:"e"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}

	jwksMu.Lock()
	defer jwksMu.Unlock()
	for _, k := range set.Keys {
		if k.Use != "sig" && k.Use != "" {
			continue
		}
		switch k.Kty {
		case "RSA":
			nBytes, _ := base64.RawURLEncoding.DecodeString(k.N)
			eBytes, _ := base64.RawURLEncoding.DecodeString(k.E)
			if len(nBytes) == 0 || len(eBytes) == 0 {
				continue
			}
			jwksKeys[k.Kid] = &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: int(new(big.Int).SetBytes(eBytes).Int64()),
			}
		case "EC":
			xBytes, _ := base64.RawURLEncoding.DecodeString(k.X)
			yBytes, _ := base64.RawURLEncoding.DecodeString(k.Y)
			if len(xBytes) == 0 || len(yBytes) == 0 {
				continue
			}
			var curve elliptic.Curve
			switch k.Crv {
			case "P-256":
				curve = elliptic.P256()
			case "P-384":
				curve = elliptic.P384()
			default:
				continue
			}
			jwksKeys[k.Kid] = &ecdsa.PublicKey{
				Curve: curve,
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			}
		}
	}
	jwksTTL = time.Now().Add(jwksCacheDuration)
	return nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
