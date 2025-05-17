package kisa

import (
	_ "context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/minus-twelve/kisa/storage"
	"github.com/minus-twelve/kisa/types"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type SecurityConfig struct {
	RateLimit      Rate
	TrustedProxies []string
	StaticCacheTTL time.Duration
}

type Rate struct {
	Period time.Duration
	Limit  int
}

type RateLimiter struct {
	attempts map[string]int
	times    map[string]time.Time
	mutex    sync.RWMutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string]int),
		times:    make(map[string]time.Time),
	}
}

func (rl *RateLimiter) Check(key string, limit int, period time.Duration) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	if last, ok := rl.times[key]; ok && now.Sub(last) < period {
		if rl.attempts[key] >= limit {
			return false
		}
		rl.attempts[key]++
	} else {
		rl.attempts[key] = 1
		rl.times[key] = now
	}
	return true
}

func (rl *RateLimiter) cleanupRateLimits() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	now := time.Now()
	for key, last := range rl.times {
		if now.Sub(last) > 5*time.Minute {
			delete(rl.attempts, key)
			delete(rl.times, key)
		}
	}
}

type SessionConfig struct {
	SessionTTL     time.Duration
	RefreshTTL     time.Duration
	CookieName     string
	SecureCookie   bool
	CSRFCookieName string
}

type SessionManager struct {
	store          Store
	config         SessionConfig
	security       SecurityConfig
	rateLimiter    *RateLimiter
	trustedProxies []net.IPNet
	shutdownChan   chan struct{}
	wg             sync.WaitGroup
}

func NewManager(store Store, config SessionConfig, security SecurityConfig) *SessionManager {
	if store == nil {
		store = NewInMemoryStore(1000) // Добавить значение по умолчанию
	}

	trustedNetworks := make([]net.IPNet, 0, len(security.TrustedProxies))
	for _, proxy := range security.TrustedProxies {
		_, ipnet, err := net.ParseCIDR(proxy)
		if err != nil {
			ip := net.ParseIP(proxy)
			if ip == nil {
				continue
			}
			mask := net.IPv4Mask(255, 255, 255, 255)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipnet = &net.IPNet{IP: ip, Mask: mask}
		}
		trustedNetworks = append(trustedNetworks, *ipnet)
	}

	manager := &SessionManager{
		store:          store,
		config:         config,
		security:       security,
		rateLimiter:    NewRateLimiter(),
		trustedProxies: trustedNetworks,
		shutdownChan:   make(chan struct{}),
	}

	manager.wg.Add(1)
	go manager.cleanupSessions()

	manager.wg.Add(1)
	go manager.cleanupRateLimits()

	go manager.handleShutdown()

	return manager
}

func (sm *SessionManager) handleShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	_ = sm.store.Cleanup(0)
	close(sm.shutdownChan)
	sm.wg.Wait()
}

func (sm *SessionManager) cleanupSessions() {
	defer sm.wg.Done()

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := sm.store.Cleanup(sm.config.SessionTTL); err != nil {
				continue
			}
		case <-sm.shutdownChan:
			return
		}
	}
}

func (sm *SessionManager) cleanupRateLimits() {
	defer sm.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.rateLimiter.cleanupRateLimits()
		case <-sm.shutdownChan:
			return
		}
	}
}

func (sm *SessionManager) CreateSession(userID, ip string) (string, string, error) {
	sessionToken, err := generateToken()
	if err != nil {
		return "", "", err
	}

	csrfToken, err := generateToken()
	if err != nil {
		return "", "", err
	}

	nonce, err := generateToken()
	if err != nil {
		return "", "", err
	}

	session := types.SessionData{
		UserID:       userID,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		IP:           ip,
		Data:         make(map[string]interface{}),
		CSRFToken:    csrfToken,
		Nonce:        nonce,
	}

	if err := sm.store.Save(sessionToken, session); err != nil {
		return "", "", err
	}

	return sessionToken, csrfToken, nil
}

func (sm *SessionManager) GenerateNonce(token string) (string, error) {
	nonce, err := generateToken()
	if err != nil {
		return "", err
	}

	session, exists := sm.GetSession(token)
	if !exists {
		return "", errors.New("session not found")
	}

	session.Nonce = nonce
	if err := sm.UpdateSession(token, session); err != nil {
		return "", err
	}

	return nonce, nil
}

func (sm *SessionManager) ValidateNonce(token, nonce string) bool {
	session, exists := sm.GetSession(token)
	if !exists {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(session.Nonce), []byte(nonce)) == 1
}

func (sm *SessionManager) InvalidateAllSessions(userID string) error {
	tokens, err := sm.store.GetAllByUserID(userID)
	if err != nil {
		return err
	}

	for _, token := range tokens {
		if err := sm.store.Delete(token); err != nil {
			return err
		}
	}
	return nil
}

func (sm *SessionManager) ValidateCSRFToken(sessionToken, csrfToken string) bool {
	session, exists := sm.GetSession(sessionToken)
	if !exists {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(csrfToken)) == 1
}

func (sm *SessionManager) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := sm.GetClientIP(c.Request)
		if !sm.rateLimiter.Check(ip, sm.security.RateLimit.Limit, sm.security.RateLimit.Period) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

func (sm *SessionManager) GetSession(token string) (types.SessionData, bool) {
	session, err := sm.store.Get(token)
	if err != nil {
		return types.SessionData{}, false
	}
	return session, true
}

func (sm *SessionManager) UpdateSession(token string, session types.SessionData) error {
	session.LastActivity = time.Now()
	return sm.store.Save(token, session)
}

func (sm *SessionManager) GetClientIP(r *http.Request) string {
	ip := r.RemoteAddr
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		for _, trusted := range sm.trustedProxies {
			clientIP := net.ParseIP(ip)
			if clientIP != nil && trusted.Contains(clientIP) {
				if ips := splitIPs(forwarded); len(ips) > 0 {
					return ips[0]
				}
			}
		}
	}
	return ip
}

func (sm *SessionManager) IsLoggedIn(r *http.Request) bool {
	cookie, err := r.Cookie(sm.config.CookieName)
	if err != nil {
		return false
	}

	session, exists := sm.GetSession(cookie.Value)
	if !exists {
		return false
	}

	if session.UserID == "" {
		return false
	}

	ip := sm.GetClientIP(r)
	return sm.ValidateSessionBinding(cookie.Value, ip)
}

func splitIPs(forwarded string) []string {
	ips := strings.Split(forwarded, ",")
	for i := range ips {
		ips[i] = strings.TrimSpace(ips[i])
	}
	return ips
}

func (sm *SessionManager) ValidateSessionBinding(token, ip string) bool { // Убрал userAgent
	session, exists := sm.GetSession(token)
	if !exists {
		return false
	}
	return session.IP == ip
}

func (sm *SessionManager) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !sm.IsLoggedIn(c.Request) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

func (sm *SessionManager) DestroySession(token string) error {
	return sm.store.Delete(token)
}

func (sm *SessionManager) CookieName() string {
	return sm.config.CookieName
}

func (sm *SessionManager) SessionTTL() time.Duration {
	return sm.config.SessionTTL
}

func (sm *SessionManager) SecureCookie() bool {
	return sm.config.SecureCookie
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (sm *SessionManager) SaveActiveSessions() error {
	if saver, ok := sm.store.(interface {
		SaveAll() error
	}); ok {
		if err := saver.SaveAll(); err != nil {
			return fmt.Errorf("failed to save sessions: %w", err)
		}
		log.Println("Active sessions saved successfully")
		return nil
	}
	log.Println("Current store doesn't support active sessions saving")
	return nil
}
