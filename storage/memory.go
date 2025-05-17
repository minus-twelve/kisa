package storage

import (
	"errors"
	"github.com/minus-twelve/kisa/types"
	"sync"
	"time"
)

type MemoryStore struct {
	sessions     map[string]types.SessionData
	userSessions map[string]map[string]struct{}
	mutex        sync.RWMutex
	maxSessions  int
}

func NewMemoryStore(maxSessions int) *MemoryStore {
	return &MemoryStore{
		sessions:     make(map[string]types.SessionData),
		userSessions: make(map[string]map[string]struct{}),
		maxSessions:  maxSessions,
	}
}

func (s *MemoryStore) GetAllByUserID(userID string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	tokensMap, exists := s.userSessions[userID]
	if !exists {
		return nil, nil
	}

	tokens := make([]string, 0, len(tokensMap))
	for token := range tokensMap {
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (s *MemoryStore) Save(token string, session types.SessionData) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.maxSessions > 0 && len(s.sessions) >= s.maxSessions {
		if oldestToken := s.findOldestSession(); oldestToken != "" {
			s.deleteInternal(oldestToken)
		} else {
			return errors.New("max sessions limit reached")
		}
	}

	for userID, tokens := range s.userSessions {
		if _, exists := tokens[token]; exists {
			delete(tokens, token)
			if len(tokens) == 0 {
				delete(s.userSessions, userID)
			}
			break
		}
	}

	s.sessions[token] = session

	if _, exists := s.userSessions[session.UserID]; !exists {
		s.userSessions[session.UserID] = make(map[string]struct{})
	}
	s.userSessions[session.UserID][token] = struct{}{}

	return nil
}

func (s *MemoryStore) findOldestSession() string {
	var oldestToken string
	var oldestTime = time.Now()

	for token, sess := range s.sessions {
		if sess.LastActivity.Before(oldestTime) {
			oldestToken = token
			oldestTime = sess.LastActivity
		}
	}
	return oldestToken
}

func (s *MemoryStore) deleteInternal(token string) {
	if session, exists := s.sessions[token]; exists {
		if tokens, ok := s.userSessions[session.UserID]; ok {
			delete(tokens, token)
			if len(tokens) == 0 {
				delete(s.userSessions, session.UserID)
			}
		}
		delete(s.sessions, token)
	}
}

func (s *MemoryStore) Get(token string) (types.SessionData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	session, exists := s.sessions[token]
	if !exists {
		return types.SessionData{}, errors.New("session not found")
	}
	return session, nil
}

func (s *MemoryStore) Delete(token string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if session, exists := s.sessions[token]; exists {
		if tokens, ok := s.userSessions[session.UserID]; ok {
			delete(tokens, token)
			if len(tokens) == 0 {
				delete(s.userSessions, session.UserID)
			}
		}
		delete(s.sessions, token)
	}
	return nil
}

func (s *MemoryStore) Cleanup(ttl time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	for token, session := range s.sessions {
		if now.Sub(session.LastActivity) > ttl {
			s.deleteInternal(token)
		}
	}
	return nil
}
