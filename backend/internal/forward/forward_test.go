package forward

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAlarmMessage(t *testing.T) {
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	got := AlarmMessage(Alarm{Instance: "siem01", Rule: `Black "list"` + "\n", Criticality: 9, Class: "BLACK"}, 2, now)
	want := `<34>1 2026-11-02T10:00:00Z siem01 blue-siem - alarm - Blue SIEM alarm: rule="Black \"list\"" criticality=9 class=BLACK`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := AlarmMessage(Alarm{Instance: "bad name", Rule: "r"}, 1, now); !strings.Contains(got, " blue-siem blue-siem ") {
		t.Errorf("invalid instance not replaced: %s", got)
	}
}

func TestForwardUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	f := New()
	f.Configure(Config{Enabled: true, Address: pc.LocalAddr().String(), Protocol: ProtoUDP})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)
	f.Send("<34>hello\n")

	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "<34>hello" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
}

func TestForwardTCPReconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Read one frame per connection, then hang up so the forwarder
			// has to reconnect.
			if msg, err := readFrame(bufio.NewReader(c)); err == nil {
				got <- msg
			}
			c.Close()
		}
	}()
	f := New()
	f.Configure(Config{Enabled: true, Address: ln.Addr().String(), Protocol: ProtoTCP})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)

	for _, want := range []string{"<34>first", "<34>second"} {
		f.Send(want)
		select {
		case m := <-got:
			if m != want {
				t.Errorf("got %q, want %q", m, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q not received; status %+v", want, f.Status())
		}
		// Give the server time to close the connection.
		time.Sleep(100 * time.Millisecond)
	}
}

// readFrame reads one octet-counted frame ("<len> <msg>").
func readFrame(r *bufio.Reader) (string, error) {
	lenStr, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(strings.TrimSpace(lenStr))
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(r, buf)
	return string(buf), err
}
