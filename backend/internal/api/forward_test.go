package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"blue-siem/internal/engine"
	"blue-siem/internal/store"
)

func TestForwarding(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	eng := engine.New(db)
	if err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Forwarder.Run(ctx)
	h := NewRouter(db, eng, Info{SyslogUDP: ":5514"}, fstest.MapFS{})
	do := func(method, url, body string) (int, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, url, strings.NewReader(body)))
		return rec.Code, rec.Body.String()
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	receive := func() string {
		t.Helper()
		pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("nothing forwarded: %v (status %+v)", err, eng.Forwarder.Status())
		}
		return string(buf[:n])
	}

	// Invalid input is rejected without storing any of the other fields.
	for _, body := range []string{
		`{"alarm_threshold": 5, "forward": {"enabled": true, "address": ""}}`,
		`{"forward": {"address": "no-port"}}`,
		`{"forward": {"address": "127.0.0.1:5514", "protocol": "udp"}}`,
		`{"forward": {"mode": "everything"}}`,
		`{"forward": {"instance": "bad name"}}`,
		`{"forward": {"severity": 8}}`,
	} {
		if code, out := do("PUT", "/api/settings", body); code != 400 {
			t.Errorf("%s: %d %s", body, code, out)
		}
	}
	if store.GetIntSetting(db, store.KeyAlarmThreshold) != 7 {
		t.Error("alarm threshold stored although the request was rejected")
	}

	code, out := do("PUT", "/api/settings", fmt.Sprintf(`{"forward": {"enabled": true, "address": %q, "min_crit": 8}}`, pc.LocalAddr().String()))
	if code != 200 {
		t.Fatalf("enable forwarding: %d %s", code, out)
	}
	var set settingsDTO
	json.Unmarshal([]byte(out), &set)
	if !set.Forward.Enabled || set.Forward.Protocol != "udp" || set.Forward.Severity != 2 || set.Forward.Mode != "original" || set.Forward.InstanceDefault == "" {
		t.Errorf("settings %+v", set.Forward)
	}

	// Criticality 7 is below the forwarding threshold, 9 (BLACK) is above.
	root := "<38>Oct 29 10:00:00 web sshd[1]: Accepted publickey for root from 1.2.3.4 port 22 ssh2"
	black := "<4>Oct 29 10:00:00 fw kernel: BLACK DROP: IN=eth0 OUT= SRC=8.8.8.8 DST=10.0.0.1 PROTO=TCP SPT=1000 DPT=22 SYN"
	eng.Process(root, "10.0.0.254")
	eng.Process(black, "10.0.0.254")
	if got, want := receive(), "<2>"+strings.TrimPrefix(black, "<4>"); got != want {
		t.Errorf("original mode:\n got  %s\n want %s", got, want)
	}

	// Alarm mode sends a new message without any details of the source.
	if code, out := do("PUT", "/api/settings", `{"forward": {"mode": "alarm", "instance": "siem-test", "severity": 1}}`); code != 200 {
		t.Fatalf("alarm mode: %d %s", code, out)
	}
	eng.Process(black, "10.0.0.254")
	got := receive()
	if !strings.HasPrefix(got, "<33>1 ") || !strings.Contains(got, " siem-test blue-siem - alarm - ") ||
		!strings.Contains(got, `rule="Blacklisted traffic (BLACK)" criticality=9 class=BLACK`) {
		t.Errorf("alarm message %s", got)
	}
	for _, secret := range []string{"8.8.8.8", "10.0.0.1", "fw", "22", "eth0", "10.0.0.254"} {
		if strings.Contains(strings.SplitN(got, " - alarm - ", 2)[1], secret) {
			t.Errorf("alarm message leaks %q: %s", secret, got)
		}
	}

	// Learning mode keeps flow-only traffic from being forwarded.
	do("PUT", "/api/settings", `{"learning_mode": true}`)
	eng.Process(black, "10.0.0.254")
	pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := pc.ReadFrom(make([]byte, 100)); err == nil {
		t.Errorf("flow-only message forwarded (%d bytes)", n)
	}

	if code, out := do("POST", "/api/forward/test", ""); code != 200 || !strings.Contains(out, "Test message") {
		t.Errorf("test endpoint: %d %s", code, out)
	}
	if got := receive(); !strings.Contains(got, `rule="Test message"`) {
		t.Errorf("test message %s", got)
	}
}
