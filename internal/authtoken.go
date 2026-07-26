package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// authSkipPaths bypass auth.
var authSkipPaths = map[string]bool{
	"/healthz": true,
	"/readyz":  true,
	"/metrics": true,
}

// authClaims are the JWT body used for service-to-service auth.
type authClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// authSecretFromEnv returns the shared secret from SERVICE_TOKEN_SECRET. In
// DEV_MODE=1 with an unset secret it returns ("", true) to signal the caller
// to bypass auth. In prod an unset secret is fatal at startup.
func authSecretFromEnv() (string, bool) {
	s := os.Getenv("SERVICE_TOKEN_SECRET")
	if s != "" {
		return s, false
	}
	if os.Getenv("DEV_MODE") == "1" {
		log.Printf("warn: SERVICE_TOKEN_SECRET unset and DEV_MODE=1; service-token auth disabled (NOT FOR PRODUCTION)")
		return "", true
	}
	log.Fatal("SERVICE_TOKEN_SECRET not set and DEV_MODE!=1; refusing to start in production mode")
	return "", false
}

// authMiddleware returns (secret, bypass) resolved from env.
func authMiddleware() (string, bool) {
	return authSecretFromEnv()
}

// applyAuth wraps h with HS256 Bearer-token auth. When bypass is true the
// middleware is a no-op (DEV_MODE with no secret configured).
func applyAuth(h http.Handler, secret string, bypass bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bypass || authSkipPaths[r.URL.Path] {
			h.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			authWriteUnauthorized(w, "missing or malformed Authorization header")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		claims, err := authVerify(token, secret)
		if err != nil {
			authWriteUnauthorized(w, err.Error())
			return
		}
		if time.Now().Unix() > claims.Exp {
			authWriteUnauthorized(w, "token expired")
			return
		}
		h.ServeHTTP(w, r)
	})
}

func authVerify(token, secret string) (*authClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := authEncode(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, errors.New("invalid signature")
	}
	body, err := authDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var c authClaims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return &c, nil
}

func authEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func authDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func authWriteUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": "unauthorized", "message": msg},
	})
}