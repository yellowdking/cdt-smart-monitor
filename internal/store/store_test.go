package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cdt-smart-monitor/internal/domain"
)

func TestStoreEncryptionAndPersistence(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	err = st.Update(func(s *domain.AppState) error {
		s.Servers = append(s.Servers, domain.Server{
			ID:              1,
			Name:            "hk-1",
			AccessKeyID:     "AKID123",
			AccessKeySecret: "SUPER_SECRET_VALUE",
		})
		s.Notify.TelegramBotToken = "12345:TG_SECRET"
		return nil
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Disk file must NOT contain plaintext secrets
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("ReadFile state.json failed: %v", err)
	}
	if strings.Contains(string(raw), "SUPER_SECRET_VALUE") || strings.Contains(string(raw), "12345:TG_SECRET") {
		t.Fatal("state.json must not store plaintext secrets")
	}

	// Masked snapshot masks secrets
	masked := st.SnapshotMasked()
	if masked.Servers[0].AccessKeySecret != "********" || masked.Notify.TelegramBotToken != "********" {
		t.Fatalf("expected masked secrets, got %+v", masked)
	}

	// Re-open decrypts secrets properly
	st2, err := Open(dir)
	if err != nil {
		t.Fatalf("re-Open failed: %v", err)
	}
	snap := st2.SnapshotRaw()
	if snap.Servers[0].AccessKeySecret != "SUPER_SECRET_VALUE" || snap.Notify.TelegramBotToken != "12345:TG_SECRET" {
		t.Fatalf("decrypted secrets mismatch: %+v", snap)
	}
}

func TestStoreUpdateRollbackOnError(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	wantErr := errors.New("abort update")
	err = st.Update(func(s *domain.AppState) error {
		s.Pool.Timezone = "America/New_York"
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if got := st.SnapshotRaw().Pool.Timezone; got != "Asia/Shanghai" {
		t.Fatalf("expected rollback to Asia/Shanghai, got %q", got)
	}
}

func TestStoreFailsOnWrongMasterKey(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := st.Update(func(s *domain.AppState) error {
		s.Notify.TelegramBotToken = "secret-token"
		return nil
	}); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Replace master.key with a different 32-byte key
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(dir, "master.key"), wrongKey, 0600); err != nil {
		t.Fatalf("overwrite master.key failed: %v", err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("expected Open to fail when master.key cannot decrypt stored secrets")
	}
}
