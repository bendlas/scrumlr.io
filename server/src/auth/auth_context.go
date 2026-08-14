package auth

import (
	"context"
	"net/http"
	"strings"

	"scrumlr.io/server/common"
	"scrumlr.io/server/identifiers"
	"scrumlr.io/server/logger"
	"scrumlr.io/server/users"

	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
)

func AuthContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, _ := jwtauth.FromContext(r.Context())
		userID := claims["id"].(string)
		user, err := uuid.Parse(userID)
		if err != nil {
			logger.FromRequest(r).Errorw("invalid user id", "user", userID, "err", err)
			http.Error(w, "invalid user id", http.StatusBadRequest)
			return
		}
		newContext := context.WithValue(r.Context(), identifiers.UserIdentifier, user)
		next.ServeHTTP(w, r.WithContext(newContext))
	})
}

// TrustedHeaderOrJWT authenticates requests from a trusted reverse proxy using
// an externally managed user identifier. If the subject header is absent or
// subjectHeader is empty, the existing JWT-cookie authentication flow is used.
//
// SECURITY: Enable this only when the backend is inaccessible except through a
// trusted reverse proxy. That proxy must strip any client-supplied copies of
// both headers before injecting its own authenticated values.
func TrustedHeaderOrJWT(
	subjectHeader string,
	nameHeader string,
	userService users.UserService,
	jwtAuth Auth,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		jwtHandler := jwtAuth.Verifier()(jwtAuth.Authenticator()(AuthContext(next)))

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subjectHeader == "" {
				jwtHandler.ServeHTTP(w, r)
				return
			}

			subject := strings.TrimSpace(r.Header.Get(subjectHeader))
			if subject == "" {
				jwtHandler.ServeHTTP(w, r)
				return
			}

			name := strings.TrimSpace(r.Header.Get(nameHeader))
			if name == "" {
				name = subject
			}

			user, err := userService.Create(r.Context(), subject, name, "", common.TrustedHeader)
			if err != nil {
				logger.FromRequest(r).Errorw(
					"unable to authenticate trusted header user",
					"err", err,
				)
				http.Error(w, "unable to authenticate trusted header user", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), identifiers.UserIdentifier, user.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
