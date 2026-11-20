package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cdt-smart-monitor/internal/domain"
)

const encPrefix = "enc:v1:"

type Store struct {
	mu        sync.RWMutex
	dataDir   string
	statePath string
	key       []byte
	state     domain.AppState
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(filepath.Join(dataDir, "master.key"))
	if err != nil {
		return nil, err
	}
	s := &Store{
		dataDir:   dataDir,
		statePath: filepath.Join(dataDir, "state.json"),
		key:       key,
		state:     domain.DefaultState(),
	}
	if raw, err := os.ReadFile(s.statePath); err == nil {
		var loaded domain.AppState
		if err := json.Unmarshal(raw, &loaded); err != nil {
			return nil, fmt.Errorf("parse state.json: %w", err)
		}
		for i := range loaded.Servers {
			if dec, err := s.decrypt(loaded.Servers[i].AccessKeySecret); err == nil {
				loaded.Servers[i].AccessKeySecret = dec
			}
		}
		if dec, err := s.decrypt(loaded.Notify.TelegramBotToken); err == nil {
			loaded.Notify.TelegramBotToken = dec
		}
		if loaded.NextServerID <= 0 {
			loaded.NextServerID = 1
		}
		if loaded.NextEventID <= 0 {
			loaded.NextEventID = 1
		}
		s.state = loaded
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Store) SnapshotMasked() domain.AppState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.cloneStateLocked()
	for i := range cp.Servers {
		if cp.Servers[i].AccessKeySecret != "" {
			cp.Servers[i].AccessKeySecret = "********"
		}
	}
	if cp.Notify.TelegramBotToken != "" {
		cp.Notify.TelegramBotToken = "********"
	}
	cp.Auth.PasswordHash = ""
	for i := range cp.Auth.Passkeys {
		cp.Auth.Passkeys[i].PublicKeyB64 = ""
	}
	return cp
}

func (s *Store) SnapshotRaw() domain.AppState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cloneStateLocked()
}

func (s *Store) Update(fn func(st *domain.AppState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.state); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Store) AddEvent(level, server, action, msg string) {
	_ = s.Update(func(st *domain.AppState) error {
		ev := domain.EventLog{
			ID:      st.NextEventID,
			Time:    time.Now().Format("2006-01-02 15:04:05"),
			Level:   level,
			Server:  server,
			Action:  action,
			Message: msg,
		}
		st.NextEventID++
		st.Events = append([]domain.EventLog{ev}, st.Events...)
		if len(st.Events) > 200 {
			st.Events = st.Events[:200]
		}
		return nil
	})
}

func (s *Store) cloneStateLocked() domain.AppState {
	cp := s.state
	cp.Servers = append([]domain.Server(nil), s.state.Servers...)
	cp.Events = append([]domain.EventLog(nil), s.state.Events...)
	cp.Auth.Passkeys = append([]domain.PasskeyCredential(nil), s.state.Auth.Passkeys...)
	return cp
}

func (s *Store) persistLocked() error {
	toSave := s.cloneStateLocked()
	for i := range toSave.Servers {
		if toSave.Servers[i].AccessKeySecret != "" {
			enc, err := s.encrypt(toSave.Servers[i].AccessKeySecret)
			if err != nil {
				return err
			}
			toSave.Servers[i].AccessKeySecret = enc
		}
	}
	if toSave.Notify.TelegramBotToken != "" {
		enc, err := s.encrypt(toSave.Notify.TelegramBotToken)
		if err != nil {
			return err
		}
		toSave.Notify.TelegramBotToken = enc
	}

	raw, err := json.MarshalIndent(toSave, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath)
}

func loadOrCreateKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil && len(raw) == 32 {
		return raw, nil
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Store) encrypt(plain string) (string, error) {
	if plain == "" || strings.HasPrefix(plain, encPrefix) {
		return plain, nil
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

func (s *Store) decrypt(val string) (string, error) {
	if !strings.HasPrefix(val, encPrefix) {
		return val, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(val, encPrefix))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
