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
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	SID       string `json:"sid"`
	IssuedAt  int64  `json:"iat"`
	Local     string `json:"-"`
	Stateless bool   `json:"-"`
}

func identityFromSession(s *sessionsapi.SessionState) sessionIdentity {
	var id sessionIdentity
	if s.OIDCSession != nil {
		id.Issuer = s.OIDCSession.Issuer
		id.Subject = s.OIDCSession.Subject
		id.SID = s.OIDCSession.SID
		id.IssuedAt = s.OIDCSession.IssuedAt
	} else {
		parts := strings.Split(s.IDToken, ".")
		if len(parts) == 3 {
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				_ = json.Unmarshal(payload, &id)
			}
		}
	}
	id.Stateless = s.OIDCSession == nil && len(s.Nonce) == 0 &&
		s.IDToken == "" && s.AccessToken == "" && s.CreatedAt == nil
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
	nextPrune   time.Time
}

func (t *sessionTracker) prune(now time.Time) {
	// Lookups below check individual deadlines. Amortize collection rather than
	// scanning every retained logout record for every authenticated request.
	if now.Before(t.nextPrune) {
		return
	}
	t.nextPrune = now.Add(time.Minute)
	for key, value := range t.revocations {
		if !value.until.IsZero() && !now.Before(value.until) {
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

func (t *sessionTracker) revokedLocked(id sessionIdentity, now time.Time) bool {
	keys := []logoutSelector{{local: id.Local}}
	if id.Issuer != "" && id.SID != "" {
		keys = append(keys, logoutSelector{issuer: id.Issuer, sid: id.SID})
	}
	if id.Issuer != "" && id.Subject != "" {
		keys = append(keys, logoutSelector{issuer: id.Issuer, subject: id.Subject})
	}
	for _, key := range keys {
		value, found := t.revocations[key]
		if found && (value.until.IsZero() || now.Before(value.until)) && matches(key, value, id) {
			return true
		}
	}
	return false
}

func (t *sessionTracker) revoked(s *sessionsapi.SessionState) bool {
	id := identityFromSession(s)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.prune(now)
	return t.revokedLocked(id, now)
}

func (t *sessionTracker) register(s *sessionsapi.SessionState, cancel context.CancelFunc) (func(), bool) {
	id := identityFromSession(s)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.prune(now)
	if t.revokedLocked(id, now) {
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
		if until, found := t.replays[replay]; found && now.Before(until) {
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
	// cookie-expire=0 creates session cookies with no server-side age limit.
	// A zero deadline represents revocation without an automatic expiration.
	value := revocation{issuedAt: issuedAt}
	if lifetime > 0 {
		value.until = now.Add(lifetime)
	}
	if old, found := t.revocations[key]; found {
		if old.issuedAt > value.issuedAt {
			value.issuedAt = old.issuedAt
		}
		if old.until.IsZero() || (!value.until.IsZero() && old.until.After(value.until)) {
			value.until = old.until
		}
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
	key := logoutSelector{local: id.Local}
	if id.Stateless {
		// Basic credentials do not identify a revocable browser login. Close
		// existing connections without blacklisting every future authentication
		// with those credentials for the entire cookie lifetime.
		t.mu.Lock()
		defer t.mu.Unlock()
		for _, conn := range t.active {
			if matches(key, revocation{}, conn.identity) {
				conn.cancel()
			}
		}
		return
	}
	t.revoke(key, 0, lifetime, "")
}

func (p *OAuthProxy) proxyWithSession(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) {
	handler := p.headersChain.Then(p.upstreamProxy)
	if s == nil || !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		handler.ServeHTTP(rw, req)
		return
	}
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	var deadline time.Time
	if s.ExpiresOn != nil {
		deadline = *s.ExpiresOn
	}
	if p.CookieOptions != nil && p.CookieOptions.Expire > 0 && s.CreatedAt != nil {
		cookieDeadline := s.CreatedAt.Add(p.CookieOptions.Expire)
		if deadline.IsZero() || cookieDeadline.Before(deadline) {
			deadline = cookieDeadline
		}
	}
	if !deadline.IsZero() {
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithDeadline(ctx, deadline)
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
