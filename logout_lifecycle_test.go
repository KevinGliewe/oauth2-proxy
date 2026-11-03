package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"golang.org/x/net/websocket"
)

// Exercise cookie serialization, normal session loading, HTTP authentication and
// real proxy upgrades together; token-only tracker tests miss minimal cookies.
func TestMinimalCookieLogoutClosesWebSocket(t *testing.T) {
	for _, selector := range []string{"sid", "subject"} {
		t.Run(selector, func(t *testing.T) {
			backend := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
				defer ws.Close()
				var msg string
				for websocket.Message.Receive(ws, &msg) == nil {
					if websocket.Message.Send(ws, msg) != nil {
						return
					}
				}
			}))
			defer backend.Close()
			opts := baseTestOptions()
			opts.Session.Cookie.Minimal = true
			if err := validation.Validate(opts); err != nil {
				t.Fatal(err)
			}
			proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse(backend.URL)
			proxy.upstreamProxy = httputil.NewSingleHostReverseProxy(target)
			session := logoutTestSession("minimal-browser", "subject", time.Now().Unix()-60)
			session.Email = "user@example.com"
			session.Nonce = []byte("browser-session-nonce")
			save := httptest.NewRecorder()
			if err := proxy.SaveSession(save, httptest.NewRequest("GET", "/", nil), session); err != nil {
				t.Fatal(err)
			}
			cookie := save.Result().Cookies()[0]
			loadReq := httptest.NewRequest("GET", "/", nil)
			loadReq.AddCookie(cookie)
			loaded, err := proxy.LoadCookiedSession(loadReq)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.IDToken != "" || loaded.OIDCSession == nil {
				t.Fatal("minimal cookie must omit tokens but retain provider identity")
			}
			server := httptest.NewServer(proxy)
			defer server.Close()
			config, _ := websocket.NewConfig("ws"+strings.TrimPrefix(server.URL, "http")+"/socket", server.URL)
			config.Header.Set("Cookie", cookie.String())
			ws, err := websocket.DialConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			_ = ws.SetDeadline(time.Now().Add(3 * time.Second))
			if err := websocket.Message.Send(ws, "hello"); err != nil {
				t.Fatal(err)
			}
			var msg string
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				t.Fatal(err)
			}
			key := logoutSelector{issuer: "https://issuer.example", sid: "minimal-browser"}
			if selector == "subject" {
				key.sid = ""
				key.subject = "subject"
			}
			token := signLifecycleLogout(t, proxy, key)
			logoutReq := httptest.NewRequest("POST", opts.ProxyPrefix+"/backchannel_logout",
				strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
			logoutReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			logoutResponse := httptest.NewRecorder()
			proxy.ServeHTTP(logoutResponse, logoutReq)
			if logoutResponse.Code != http.StatusOK {
				t.Fatalf("logout status %d: %s", logoutResponse.Code, logoutResponse.Body.String())
			}
			if err := websocket.Message.Receive(ws, &msg); err == nil {
				t.Fatal("logout left minimal-cookie socket open")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("socket timed out instead of closing")
			}
			// A copied cookie must not reauthorize HTTP or upgrade requests.
			authReq := httptest.NewRequest("GET", "/oauth2/auth", nil)
			authReq.AddCookie(cookie)
			auth := httptest.NewRecorder()
			proxy.ServeHTTP(auth, authReq)
			if auth.Code != http.StatusUnauthorized {
				t.Fatalf("revoked auth status %d", auth.Code)
			}
			if fresh, err := websocket.DialConfig(config); err == nil {
				fresh.Close()
				t.Fatal("minimal cookie reconnected after logout")
			}
		})
	}
}

type refreshFailureProvider struct {
	providers.Provider
	calls *int
}

func (p refreshFailureProvider) RefreshSession(context.Context, *sessionsapi.SessionState) (bool, error) {
	(*p.calls)++
	return false, errors.New("invalid_grant")
}

func TestLogoutWithFailedRefreshClosesConnections(t *testing.T) {
	opts := baseTestOptions()
	opts.Cookie.Refresh = time.Second
	if err := validation.Validate(opts); err != nil {
		t.Fatal(err)
	}
	p, err := NewOAuthProxy(opts, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	p.sessionChain = buildSessionChain(opts, refreshFailureProvider{p.provider, &calls}, p.sessionStore, nil, &p.sessionTracker)
	p.buildServeMux(opts.ProxyPrefix)
	session := logoutTestSession("failed-refresh", "subject", time.Now().Unix()-60)
	session.Email = "user@example.com"
	session.Nonce = []byte("stable-browser-identity")
	created := time.Now().Add(-time.Minute)
	session.CreatedAt = &created
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remove, ok := p.sessionTracker.register(session, cancel)
	if !ok {
		t.Fatal("registration failed")
	}
	defer remove()
	save := httptest.NewRecorder()
	if err := p.sessionStore.Save(save, httptest.NewRequest("GET", "/", nil), session); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/oauth2/sign_out", nil)
	req.AddCookie(save.Result().Cookies()[0])
	response := httptest.NewRecorder()
	p.ServeHTTP(response, req)
	if calls != 1 {
		t.Fatalf("expected fatal refresh, got %d calls", calls)
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("discarding failed-refresh session left WebSocket connected")
	}
	if !p.sessionTracker.revoked(session) {
		t.Fatal("invalidated session can reconnect")
	}
}

func TestRevokedCookieIsRejectedBeforeRefresh(t *testing.T) {
	opts := baseTestOptions()
	opts.Cookie.Refresh = time.Second
	if err := validation.Validate(opts); err != nil {
		t.Fatal(err)
	}
	p, err := NewOAuthProxy(opts, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	p.sessionChain = buildSessionChain(opts, refreshFailureProvider{p.provider, &calls}, p.sessionStore, nil, &p.sessionTracker)
	p.buildServeMux(opts.ProxyPrefix)
	session := logoutTestSession("revoked", "subject", time.Now().Unix()-60)
	session.Email = "user@example.com"
	created := time.Now().Add(-time.Minute)
	session.CreatedAt = &created
	save := httptest.NewRecorder()
	if err := p.sessionStore.Save(save, httptest.NewRequest("GET", "/", nil), session); err != nil {
		t.Fatal(err)
	}
	p.sessionTracker.revoke(logoutSelector{issuer: "https://issuer.example", subject: "subject"}, time.Now().Unix(), time.Hour, "")
	req := httptest.NewRequest("GET", "/oauth2/auth", nil)
	req.AddCookie(save.Result().Cookies()[0])
	response := httptest.NewRecorder()
	p.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("revoked session status %d, refresh calls %d", response.Code, calls)
	}
}

func TestManualBrowserSessionIdentitySurvivesRefresh(t *testing.T) {
	opts := baseTestOptions()
	if err := validation.Validate(opts); err != nil {
		t.Fatal(err)
	}
	p, err := NewOAuthProxy(opts, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	s := &sessionsapi.SessionState{User: "manual-user"}
	if err := p.SaveSession(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), s); err != nil {
		t.Fatal(err)
	}
	if len(s.Nonce) == 0 {
		t.Fatal("browser login lacks stable identity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remove, ok := p.sessionTracker.register(s, cancel)
	if !ok {
		t.Fatal("registration failed")
	}
	defer remove()
	refreshed := *s
	refreshed.CreatedAtNow()
	p.sessionTracker.logoutSession(&refreshed, time.Hour)
	if ctx.Err() == nil {
		t.Fatal("refreshed browser login did not close original socket")
	}
}

// Use a real signed token and JWKS endpoint for the full cookie/socket lifecycle.
func signLifecycleLogout(t *testing.T, p *OAuthProxy, selector logoutSelector) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(keys.Close)
	p.provider.Data().LogoutVerifier = oidc.NewVerifier(selector.issuer,
		oidc.NewRemoteKeySet(context.Background(), keys.URL), &oidc.Config{ClientID: "client", SkipExpiryCheck: true})
	claims := map[string]interface{}{"iss": selector.issuer, "aud": "client", "iat": time.Now().Unix(),
		"jti": "lifecycle", "events": map[string]interface{}{backchannelLogoutEvent: map[string]interface{}{}}}
	if selector.sid != "" {
		claims["sid"] = selector.sid
	}
	if selector.subject != "" {
		claims["sub"] = selector.subject
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
