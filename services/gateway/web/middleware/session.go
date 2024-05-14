package middleware

import (
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/nicedoc/onlyoffice-biyue/services/shared"
	"golang.org/x/oauth2"
)

type SessionMiddleware struct {
	jwtManager  crypto.JwtManager
	store       *sessions.CookieStore
	credentials *oauth2.Config
	onlyoffice  *shared.OnlyofficeConfig
	logger      log.Logger
}

func NewSessionMiddleware(
	jwtManager crypto.JwtManager,
	credentials *oauth2.Config,
	onlyoffice *shared.OnlyofficeConfig,
	logger log.Logger,
) SessionMiddleware {
	return SessionMiddleware{
		jwtManager:  jwtManager,
		store:       sessions.NewCookieStore([]byte(credentials.ClientSecret)),
		credentials: credentials,
		onlyoffice:  onlyoffice,
		logger:      logger,
	}
}

func (m SessionMiddleware) saveRedirectURL(rw http.ResponseWriter, r *http.Request) {
	session, _ := m.store.Get(r, "url")
	session.Values["redirect"] = m.onlyoffice.Onlyoffice.Builder.GatewayURL + r.URL.String()

	if err := session.Save(r, rw); err != nil {
		m.logger.Warn("could not save session")
	}
}

func (m SessionMiddleware) saveXToken(rw http.ResponseWriter, r *http.Request) {
	session, _ := m.store.Get(r, "auth-installation")
	xtoken := r.URL.Query().Get("xtoken")
	if xtoken != "" {
		session.Values["X-Token"] = xtoken
	}

	if err := session.Save(r, rw); err != nil {
		m.logger.Warn("could not save session")
	}
}

func (m SessionMiddleware) Protect(next http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		session, err := m.store.Get(r, "authorization")
		if err != nil {
			m.logger.Errorf("could not get session for current user: %s", err.Error())
			m.saveRedirectURL(rw, r)
			m.saveXToken(rw, r)
			http.Redirect(rw, r.WithContext(r.Context()), "/oauth/install", http.StatusSeeOther)
			return
		}

		val, ok := session.Values["token"].(string)
		if !ok {
			m.logger.Debug("could not cast token to string, %v", session)
			session.Options.MaxAge = -1
			if err := session.Save(r, rw); err != nil {
				m.logger.Warnf("could not save a cookie session: %w", err)
			}
			m.saveRedirectURL(rw, r)
			m.saveXToken(rw, r)
			http.Redirect(rw, r.WithContext(r.Context()), "/oauth/install", http.StatusSeeOther)
			return
		}

		var token jwt.MapClaims
		if err := m.jwtManager.Verify(m.credentials.ClientSecret, val, &token); err != nil {
			m.logger.Debugf("could not verify session token: %s", err.Error())
			session.Options.MaxAge = -1
			if err := session.Save(r, rw); err != nil {
				m.logger.Warnf("could not save a cookie session: %w", err)
			}
			m.saveRedirectURL(rw, r)
			m.saveXToken(rw, r)
			http.Redirect(rw, r.WithContext(r.Context()), "/oauth/install", http.StatusSeeOther)
			return
		}

		if token["jti"] == "" {
			session.Options.MaxAge = -1
			if err := session.Save(r, rw); err != nil {
				m.logger.Warnf("could not save a cookie session: %w", err)
			}
			m.saveRedirectURL(rw, r)
			m.saveXToken(rw, r)
			http.Redirect(rw, r.WithContext(r.Context()), "/oauth/install", http.StatusSeeOther)
			return
		}

		xtoken := r.URL.Query().Get("xtoken")
		if xtoken != "" && session.Values["X-Token"] != nil {
			if session.Values["X-Token"] != xtoken {
				session.Options.MaxAge = -1
				if err := session.Save(r, rw); err != nil {
					m.logger.Warnf("could not save a cookie session: %w", err)
				}
				m.saveRedirectURL(rw, r)
				m.saveXToken(rw, r)
				http.Redirect(rw, r.WithContext(r.Context()), "/oauth/install", http.StatusSeeOther)
				return
			}
		}

		signature, _ := m.jwtManager.Sign(m.credentials.ClientSecret, jwt.RegisteredClaims{
			ID:        token["jti"].(string),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
		})
		session.Values["token"] = signature
		session.Options.MaxAge = 60 * 60 * 24
		if err := session.Save(r, rw); err != nil {
			m.logger.Errorf("could not save session token: %s", err.Error())
		} else {
			m.logger.Debugf("refreshed current session: %s", signature)
		}

		rw.Header().Set("X-User", token["jti"].(string))
		next.ServeHTTP(rw, r)
	}

	return http.HandlerFunc(fn)
}
