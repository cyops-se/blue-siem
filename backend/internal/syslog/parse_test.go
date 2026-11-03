package syslog

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.Local)
	tests := []struct {
		name, raw                   string
		format, host, app, pid, msg string
		facility, severity          int
	}{
		{
			name: "rfc3164", raw: "<38>Oct 29 11:59:01 web01 sshd[1234]: Failed password for root from 10.0.0.5 port 2222 ssh2",
			format: FormatRFC3164, host: "web01", app: "sshd", pid: "1234",
			msg: "Failed password for root from 10.0.0.5 port 2222 ssh2", facility: 4, severity: 6,
		},
		{
			name: "rfc3164 kernel", raw: "<4>Oct  9 08:00:00 fw kernel: [123.456] BLACK DROP: IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8",
			format: FormatRFC3164, host: "fw", app: "kernel",
			msg: "[123.456] BLACK DROP: IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8", facility: 0, severity: 4,
		},
		{
			name: "rfc3164 without host", raw: "<13>Oct 29 11:00:00 sudo: erik : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
			format: FormatRFC3164, app: "sudo", msg: "erik : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", facility: 1, severity: 5,
		},
		{
			name: "rfc3339 timestamp", raw: "<14>2026-10-29T10:00:00.123+01:00 host2 app: hello",
			format: FormatRFC3164, host: "host2", app: "app", msg: "hello", facility: 1, severity: 6,
		},
		{
			name: "rfc5424", raw: `<165>1 2026-10-29T10:00:00Z host3 myapp 99 ID47 [ex@1 a="b\]c"][x@2 k="v"] BOMhello world`,
			format: FormatRFC5424, host: "host3", app: "myapp", pid: "99", msg: "BOMhello world", facility: 20, severity: 5,
		},
		{
			name: "rfc5424 nil sd", raw: "<34>1 - - su - - - 'su root' failed",
			format: FormatRFC5424, app: "su", msg: "'su root' failed", facility: 4, severity: 2,
		},
		{
			name: "raw", raw: "just some text",
			format: FormatRaw, msg: "just some text", facility: 1, severity: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Parse(tt.raw, now)
			if m.Format != tt.format || m.Hostname != tt.host || m.AppName != tt.app ||
				m.ProcID != tt.pid || m.Message != tt.msg || m.Facility != tt.facility || m.Severity != tt.severity {
				t.Errorf("got %+v", m)
			}
		})
	}
}

func TestParse3164Year(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 10, 0, 0, time.Local)
	m := Parse("<13>Dec 31 23:59:00 h a: x", now)
	if m.Timestamp.Year() != 2025 {
		t.Errorf("year = %d, want 2025", m.Timestamp.Year())
	}
}

func TestWithSeverity(t *testing.T) {
	tests := []struct{ raw, want string }{
		{"<38>Oct 29 11:59:01 web01 sshd[1]: Failed password\n", "<34>Oct 29 11:59:01 web01 sshd[1]: Failed password"},
		{"<165>1 2026-10-29T10:00:00Z host3 myapp 99 ID47 - hello", "<162>1 2026-10-29T10:00:00Z host3 myapp 99 ID47 - hello"},
		{"just some text", "<10>just some text"},
	}
	facilities := []int{4, 20, 1}
	for i, tt := range tests {
		if got := WithSeverity(tt.raw, facilities[i], 2); got != tt.want {
			t.Errorf("WithSeverity(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestParseStructuredData(t *testing.T) {
	m := Parse(`<134>1 2026-10-29T12:13:41.484071Z WS01 blue-fwd - 1 [win@32473 channel="Microsoft-Windows-Sysmon/Operational" eventId="1" note="a \"q\" \] b\\c"][x@1 k="v"] {"EventID":1}`, time.Now())
	if m.Format != FormatRFC5424 || m.MsgID != "1" || m.Message != `{"EventID":1}` {
		t.Fatalf("got %+v", m)
	}
	win := m.StructuredData["win@32473"]
	if win["channel"] != "Microsoft-Windows-Sysmon/Operational" || win["eventId"] != "1" || win["note"] != `a "q" ] b\c` || m.StructuredData["x@1"]["k"] != "v" {
		t.Errorf("structured data %v", m.StructuredData)
	}
	if m := Parse("<14>1 - h app - - - text", time.Now()); m.StructuredData != nil || m.Message != "text" {
		t.Errorf("nil SD: %+v", m)
	}
}
