package engine

import (
	"fmt"
	"path/filepath"
	"testing"

	"blue-siem/internal/models"
	"blue-siem/internal/store"
)

func TestParseIPTables(t *testing.T) {
	msg := "[ 1234.567890] GREY-DROP: IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=203.0.113.9 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=54321 DF PROTO=TCP SPT=40000 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0"
	f, ok := ParseIPTables(msg)
	if !ok {
		t.Fatal("not recognised")
	}
	want := map[string]string{
		"prefix": "GREY-DROP:", "in_iface": "eth0", "out_iface": "", "src_ip": "203.0.113.9",
		"dst_ip": "192.168.1.10", "proto": "TCP", "src_port": "40000", "dst_port": "22",
		"flags": "DF SYN", "action": "DROP", "direction": "inbound", "window": "29200",
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s = %q, want %q", k, f[k], v)
		}
	}
	if _, ok := ParseIPTables("Failed password for root from 1.2.3.4"); ok {
		t.Error("non iptables message recognised")
	}
}

func newEngine(t *testing.T) *Engine {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	db.Create(&[]models.IPListEntry{
		{List: models.ClassBlack, CIDR: "198.51.100.0/24"},
		{List: models.ClassWhite, CIDR: "192.168.1.0/24"},
	})
	e := New(db)
	if err := e.Reload(); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAnalyze(t *testing.T) {
	e := newEngine(t)
	const fw = "<4>Oct 29 10:00:00 fw kernel: [1.0] %sIN=eth0 OUT= SRC=%s DST=10.0.0.1 PROTO=TCP SPT=5555 DPT=%s SYN"
	tests := []struct {
		name, raw, decoder, class string
		crit                      int
		alarm                     bool
	}{
		{"prefix black", fmt.Sprintf(fw, "BLACK DROP: ", "8.8.8.8", "80"), "iptables", "BLACK", 9, true},
		{"list black", fmt.Sprintf(fw, "FW: ", "198.51.100.7", "80"), "iptables", "BLACK", 9, true},
		{"list white", fmt.Sprintf(fw, "DROP: ", "192.168.1.20", "22"), "iptables", "WHITE", 1, false},
		{"grey accept", fmt.Sprintf(fw, "GREY ACCEPT: ", "8.8.8.8", "80"), "iptables", "GREY", 7, true},
		{"grey by default", fmt.Sprintf(fw, "FW: ", "8.8.8.8", "80"), "iptables", "GREY", 7, true},
		{"grey sensitive port", fmt.Sprintf(fw, "", "8.8.8.8", "3389"), "iptables", "GREY", 8, true},
		{"ssh failed", "<38>Oct 29 10:00:00 web sshd[1]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2", "sshd-failed", "", 5, false},
		{"root login", "<38>Oct 29 10:00:00 web sshd[1]: Accepted publickey for root from 1.2.3.4 port 22 ssh2", "sshd-accepted", "", 7, true},
		{"sudo bad pw", "<85>Oct 29 10:00:00 web sudo: erik : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/erik ; USER=root ; COMMAND=/bin/sh", "sudo", "", 7, true},
		{"crit severity", "<2>Oct 29 10:00:00 web app: disk on fire", "", "", 8, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := e.Analyze(tt.raw, "10.0.0.254")
			ev := r.Event
			if ev.Decoder != tt.decoder || ev.Criticality != tt.crit || r.Alarm != tt.alarm {
				t.Errorf("decoder=%q crit=%d alarm=%v rules=%v fields=%v", ev.Decoder, ev.Criticality, r.Alarm, r.Matched, ev.Fields)
			}
			if tt.class != "" && !ev.Tags.Has(tt.class) {
				t.Errorf("tags %v missing %s", ev.Tags, tt.class)
			}
		})
	}
}

func TestProcessCreatesAlarm(t *testing.T) {
	e := newEngine(t)
	ev, alarm, err := e.Process("<4>Oct 29 10:00:00 fw kernel: BLACK DROP: IN=eth0 OUT= SRC=8.8.8.8 DST=10.0.0.1 PROTO=UDP SPT=53 DPT=5353", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if alarm == nil || ev.AlarmID == nil || *ev.AlarmID != alarm.ID {
		t.Fatalf("expected alarm, got event=%+v alarm=%+v", ev, alarm)
	}
	var stored models.Event
	e.db.First(&stored, ev.ID)
	if !stored.Tags.Has("BLACK") || stored.Fields["src_ip"] != "8.8.8.8" || stored.AlarmID == nil {
		t.Errorf("stored event %+v", stored)
	}
}
