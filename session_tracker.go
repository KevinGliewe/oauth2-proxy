package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// sessionIdentity is derived only from a session that has already been authenticated.
// Never use identityFromSession to validate an incoming logout token.
type sessionIdentity struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	SID      string `json:"sid"`
	IssuedAt int64  `json:"iat"`
	Local    string `json:"-"`
}

func identityFromSession(s *sessionsapi.SessionState) sessionIdentity {
	var id sessionIdentity
	parts := strings.Split(s.IDToken, ".")
	if len(parts) == 3 {
		if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(payload, &id)
		}
	}
	if s.LogoutIssuedAt != 0 {
		id.IssuedAt = s.LogoutIssuedAt
	}
	// Nonce survives token refresh and distinguishes separate browser logins.
	key := s.IDToken
	if len(s.Nonce) != 0 {
		key = string(s.Nonce)
	} else if key == "" {
		key = fmt.Sprintf("%s:%s:%v", s.User, s.AccessToken, s.CreatedAt)
	}
	id.Local = fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	return id
}

type logoutSelector struct{ issuer, sid, subject, local string }
type revocation struct {
	until    time.Time
	issuedAt int64
}
type trackedConnection struct {
	identity sessionIdentity
	cancel   context.CancelFunc
}

// sessionTracker is process local. Registration and revocation share a lock so
// logout cannot miss a connection between authorization and the upgrade.
type sessionTracker struct {
	mu          sync.Mutex
	next        uint64
	active      map[uint64]trackedConnection
	revocations map[logoutSelector]revocation
	replays     map[string]time.Time
}

func (t *sessionTracker) prune(now time.Time) {
	for key, value := range t.revocations {
		if !now.Before(value.until) {
			delete(t.revocations, key)
		}
	}
	for key, until := range t.replays {
		if !now.Before(until) {
			delete(t.replays, key)
		}
	}
}

func matches(key logoutSelector, value revocation, id sessionIdentity) bool {
	if key.local != "" {
		return key.local == id.Local
	}
	if key.issuer != id.Issuer {
		return false
	}
	if key.sid != "" {
		return key.sid == id.SID
	}
	return key.subject == id.Subject && (id.IssuedAt == 0 || id.IssuedAt <= value.issuedAt)
}

func (t *sessionTracker) revokedLocked(id sessionIdentity) bool {
	for key, value := range t.revocations {
		if matches(key, value, id) {
			return true
		}
	}
	return false
}

func (t *sessionTracker) revoked(s *sessionsapi.SessionState) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(time.Now())
	return t.revokedLocked(identityFromSession(s))
}

func (t *sessionTracker) register(s *sessionsapi.SessionState, cancel context.CancelFunc) (func(), bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(time.Now())
	id := identityFromSession(s)
	if t.revokedLocked(id) {
		return nil, false
	}
	if t.active == nil {
		t.active = make(map[uint64]trackedConnection)
	}
	t.next++
	key := t.next
	t.active[key] = trackedConnection{id, cancel}
	return func() {
		t.mu.Lock()
		delete(t.active, key)
		t.mu.Unlock()
	}, true
}

func (t *sessionTracker) revoke(key logoutSelector, issuedAt int64, lifetime time.Duration, replay string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.prune(now)
	if replay != "" {
		if _, found := t.replays[replay]; found {
			return false
		}
		if t.replays == nil {
			t.replays = make(map[string]time.Time)
		}
		t.replays[replay] = now.Add(logoutTokenMaxAge + time.Minute)
	}
	if t.revocations == nil {
		t.revocations = make(map[logoutSelector]revocation)
	}
	value := revocation{now.Add(lifetime), issuedAt}
	if old := t.revocations[key]; old.issuedAt > value.issuedAt {
		value.issuedAt = old.issuedAt
	}
	t.revocations[key] = value
	for _, conn := range t.active {
		if matches(key, value, conn.identity) {
			conn.cancel()
		}
	}
	return true
}

func (t *sessionTracker) logoutSession(s *sessionsapi.SessionState, lifetime time.Duration) {
	id := identityFromSession(s)
	t.revoke(logoutSelector{local: id.Local}, 0, lifetime, "")
}

func (p *OAuthProxy) proxyWithSession(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) {
	handler := p.headersChain.Then(p.upstreamProxy)
	if s == nil || !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		handler.ServeHTTP(rw, req)
		return
	}
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	if s.ExpiresOn != nil {
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithDeadline(ctx, *s.ExpiresOn)
		defer deadlineCancel()
	}
	remove, ok := p.sessionTracker.register(s, cancel)
	if !ok {
		http.Error(rw, "Session logged out", http.StatusUnauthorized)
		return
	}
	defer remove()
	// ReverseProxy closes both ends of an upgraded connection on cancellation.
	handler.ServeHTTP(rw, req.WithContext(ctx))
}
