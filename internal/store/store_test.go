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

func TestStoreOpenDefaultsAndNextIDs(t *testing.T) {
	dir := t.TempDir()
	// Simulate an older/partial state.json missing newer fields and with stale NextServerID/NextEventID.
	partial := `{
  "next_server_id": 2,
  "next_event_id": 1,
  "pool": {
    "enabled": false
  },
  "servers": [
    {"id": 2, "name": "hk-1"},
    {"id": 7, "name": "jp-2"}
  ],
  "events": [
    {"id": 42, "action": "init"}
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(partial), 0600); err != nil {
		t.Fatalf("write partial state.json failed: %v", err)
	}

	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open partial state failed: %v", err)
	}
	snap := st.SnapshotRaw()
	if snap.Pool.Enabled {
		t.Fatal("expected explicit pool.enabled=false to be preserved")
	}
	if snap.Pool.Timezone != "Asia/Shanghai" {
		t.Fatalf("expected missing timezone to inherit default Asia/Shanghai, got %q", snap.Pool.Timezone)
	}
	if snap.Pool.PollIntervalMinutes != 5 || snap.Pool.DefaultMaxTrafficGB != 200 {
		t.Fatalf("expected missing pool defaults to be populated, got %+v", snap.Pool)
	}
	if !snap.Notify.WeeklyReportEnabled {
		t.Fatal("expected missing notify.weekly_report_enabled to inherit default true")
	}
	if snap.NextServerID != 8 {
		t.Fatalf("expected NextServerID > max(existing IDs)=7, got %d", snap.NextServerID)
	}
	if snap.NextEventID != 43 {
		t.Fatalf("expected NextEventID > max(existing event IDs)=42, got %d", snap.NextEventID)
	}
}
