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
			dec, err := s.decrypt(loaded.Servers[i].AccessKeySecret)
			if err != nil {
				return nil, fmt.Errorf("decrypt server %q secret (check master.key): %w", loaded.Servers[i].Name, err)
			}
			loaded.Servers[i].AccessKeySecret = dec
		}
		if loaded.Notify.TelegramBotToken != "" {
			dec, err := s.decrypt(loaded.Notify.TelegramBotToken)
			if err != nil {
				return nil, fmt.Errorf("decrypt telegram bot token (check master.key): %w", err)
			}
			loaded.Notify.TelegramBotToken = dec
		}
		if loaded.NextServerID <= 0 {
			loaded.NextServerID = 1
		}
		if loaded.NextEventID <= 0 {
			loaded.NextEventID = 1
		}
		if loaded.Servers == nil {
			loaded.Servers = []domain.Server{}
		}
		if loaded.Events == nil {
			loaded.Events = []domain.EventLog{}
		}
		if loaded.Auth.Passkeys == nil {
			loaded.Auth.Passkeys = []domain.PasskeyCredential{}
		}
		if loaded.Pool.ManualAutoRevertMode == "" {
			loaded.Pool.ManualAutoRevertMode = domain.ManualRevertNextSlot
			loaded.Pool.ManualOverridesAutoResetDaily = true
		}
		if loaded.Pool.ManualAutoRevertMinutes <= 0 {
			loaded.Pool.ManualAutoRevertMinutes = 120
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
	cp := cloneState(s.state)
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
	return cloneState(s.state)
}

// Update runs fn against a cloned draft state and commits it atomically only if both fn and disk persistence succeed.
func (s *Store) Update(fn func(st *domain.AppState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft := cloneState(s.state)
	if err := fn(&draft); err != nil {
		return err
	}
	if err := s.persistStateLocked(draft); err != nil {
		return err
	}
	s.state = draft
	return nil
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

func cloneState(st domain.AppState) domain.AppState {
	cp := st
	if st.Servers == nil {
		cp.Servers = []domain.Server{}
	} else {
		cp.Servers = append([]domain.Server(nil), st.Servers...)
	}
	if st.Events == nil {
		cp.Events = []domain.EventLog{}
	} else {
		cp.Events = append([]domain.EventLog(nil), st.Events...)
	}
	if st.Auth.Passkeys == nil {
		cp.Auth.Passkeys = []domain.PasskeyCredential{}
	} else {
		cp.Auth.Passkeys = append([]domain.PasskeyCredential(nil), st.Auth.Passkeys...)
	}
	if len(st.Pool.ManualHourlyOverrides) > 0 {
		m := make(map[int]int64, len(st.Pool.ManualHourlyOverrides))
		for k, v := range st.Pool.ManualHourlyOverrides {
			m[k] = v
		}
		cp.Pool.ManualHourlyOverrides = m
	} else {
		cp.Pool.ManualHourlyOverrides = nil
	}
	return cp
}

func (s *Store) persistStateLocked(st domain.AppState) error {
	toSave := cloneState(st)
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
	return writeFileAtomic(s.dataDir, s.statePath, raw, 0600)
}

func writeFileAtomic(dir, targetPath string, data []byte, perm os.FileMode) error {
	tmpFile, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) == 32 {
			return raw, nil
		}
		return nil, fmt.Errorf("invalid master.key length: expected 32 bytes, got %d", len(raw))
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Dir(path), path, key, 0600); err != nil {
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
