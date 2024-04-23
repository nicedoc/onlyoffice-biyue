/**
 *
 * (c) Copyright Ascensio System SIA 2023
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package controller

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/nicedoc/onlyoffice-biyue/services/gateway/web/embeddable"
	"github.com/nicedoc/onlyoffice-biyue/services/shared"
	aclient "github.com/nicedoc/onlyoffice-biyue/services/shared/client"
	"github.com/nicedoc/onlyoffice-biyue/services/shared/response"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
)

type AuthController struct {
	client         client.Client
	api            aclient.MinioClient
	jwtManager     crypto.JwtManager
	stateGenerator crypto.StateGenerator
	store          *sessions.CookieStore
	config         *config.ServerConfig
	oauth          *oauth2.Config
	logger         log.Logger
	biyueConfig    *shared.BiyueConfig
}

func NewAuthController(
	client client.Client,
	api aclient.MinioClient,
	jwtManager crypto.JwtManager,
	stateGenerator crypto.StateGenerator,
	config *config.ServerConfig,
	oauth *oauth2.Config,
	logger log.Logger,
	biyueConfig *shared.BiyueConfig,
) AuthController {
	return AuthController{
		client:         client,
		api:            api,
		jwtManager:     jwtManager,
		stateGenerator: stateGenerator,
		store:          sessions.NewCookieStore([]byte(oauth.ClientSecret)),
		config:         config,
		oauth:          oauth,
		logger:         logger,
		biyueConfig:    biyueConfig,
	}
}

func (c AuthController) getRedirectURL(rw http.ResponseWriter, r *http.Request) string {
	session, _ := c.store.Get(r, "url")
	url := "https://eduteacher.xmdas-link.com/question/"

	if val, ok := session.Values["redirect"].(string); ok {
		url = val
	}

	session.Options.MaxAge = -1
	if err := session.Save(r, rw); err != nil {
		c.logger.Warnf("could not save a cookie session: %w", err)
	}

	return url
}

func (c AuthController) BuildTest() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("X-Token", c.biyueConfig.Biyue.ApiTestToken)
		session, _ := c.store.Get(r, "auth-installation")
		session.Values["X-Token"] = c.biyueConfig.Biyue.ApiTestToken
		if err := session.Save(r, rw); err != nil {
			c.logger.Debugf("could not save session. Reason: %s", err.Error())
		}

		if err := embeddable.TestPage.Execute(rw, nil); err != nil {
			c.logger.Errorf("could not execute a test template: %w", err)
		}
	}
}

func (c AuthController) BuildGetAuth() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		v, _ := cv.CreateCodeVerifier()
		verifier := v.String()

		session, _ := c.store.Get(r, "auth-installation")
		session.Values["verifier"] = verifier
		state, err := c.stateGenerator.GenerateState(verifier)
		if err != nil {
			c.logger.Debugf("could not generate a new state. Reason: %s", err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		session.Values["state"] = state
		c.logger.Debug("set session state: ", state)

		xtoken := r.Header.Get("X-Token")
		if xtoken == "" {
			if session.Values["X-Token"] == nil {
				http.Redirect(rw, r, c.biyueConfig.Biyue.AuthEndPoint, http.StatusMovedPermanently)
				return
			}
			xtoken = session.Values["X-Token"].(string)
		}
		session.Values["X-Token"] = xtoken
		c.logger.Debugf("set session token: %s", xtoken)

		if err := session.Save(r, rw); err != nil {
			c.logger.Debugf("could not save session. Reason: %s", err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		http.Redirect(rw, r.WithContext(r.Context()),
			fmt.Sprintf("/oauth/redirect?state=%s&code=%s", state, verifier),
			http.StatusSeeOther)

		// http.Redirect(
		// 	rw, r,
		// 	fmt.Sprintf(
		// 		"%s?response_type=%s&client_id=%s&redirect_uri=%s&token_access_type=%s&state=%s&code_challenge=%s&code_challenge_method=%s&force_reapprove=true&disable_signup=true&scope=openid",
		// 		"/oauth/redirect",
		// 		"code",
		// 		c.oauth.ClientID,
		// 		url.QueryEscape(c.oauth.RedirectURL),
		// 		"offline",
		// 		url.QueryEscape(state),
		// 		v.CodeChallengeS256(),
		// 		"S256",
		// 	),
		// 	http.StatusMovedPermanently,
		// )
	}
}

func (c AuthController) BuildGetRedirect() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		tctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		query := r.URL.Query()
		code, state := strings.TrimSpace(query.Get("code")), strings.TrimSpace(query.Get("state"))
		if code == "" || state == "" {
			c.logger.Debug("empty auth code or state parameter")
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		errMsg := map[string]interface{}{
			"errorMain":    "Installation Failed",
			"errorSubtext": "Please try again or contact admin",
			"closeButton":  "Close",
		}

		session, err := c.store.Get(r, "auth-installation")
		if err != nil {
			c.logger.Debugf("could not get session store: %s", err.Error())
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		xtoken := session.Values["X-Token"].(string)
		t := &oauth2.Token{
			AccessToken:  xtoken,
			RefreshToken: xtoken,
			TokenType:    "Bearer",
		}
		t = t.WithExtra(map[string]interface{}{
			"scope": "openid offline",
		})

		c.logger.Debugf("get token ok: %v", t)

		usr, err := c.api.GetUser(tctx, t.AccessToken)
		if err != nil {
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		c.logger.Debugf("get user ok: %s", usr.UserID)

		var resp interface{}
		if err := c.client.Call(r.Context(), c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.config.Namespace),
			"UserInsertHandler.InsertUser",
			response.UserResponse{
				ID:           usr.UserID,
				AccessToken:  t.AccessToken,
				RefreshToken: t.RefreshToken,
				TokenType:    t.TokenType,
				Scope:        t.Extra("scope").(string),
				Expiry:       t.Expiry.UTC().Format(time.RFC3339),
			},
		), &resp, client.WithRetries(3)); err != nil {
			c.logger.Errorf("could not insert a new user: %s", err.Error())
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		session, _ = c.store.Get(r, "authorization")
		tkn, err := c.jwtManager.Sign(c.oauth.ClientSecret, jwt.RegisteredClaims{
			ID:        usr.UserID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
		})

		if err != nil {
			c.logger.Errorf("could not issue a new jwt: %s", err.Error())
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		session.Values["token"] = tkn
		session.Options.MaxAge = 60 * 60 * 24
		if err := session.Save(r, rw); err != nil {
			c.logger.Errorf("could not save current session: %s", err.Error())
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}
		c.logger.Debugf("[after auth session]: %v", session)

		http.Redirect(rw, r, c.getRedirectURL(rw, r), http.StatusMovedPermanently)
	}
}
