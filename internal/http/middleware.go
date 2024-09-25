package http

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/AlchemillaHQ/simple-turn/internal/config"
)

func basicAuthMiddleware(next http.HandlerFunc, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Basic ") {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		payload, _ := base64.StdEncoding.DecodeString(authHeader[6:])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 || subtle.ConstantTimeCompare([]byte(pair[0]), []byte(cfg.Username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pair[1]), []byte(cfg.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}
