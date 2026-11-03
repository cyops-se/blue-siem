// Package forward relays messages to another syslog server over UDP or TCP.
// Sending happens on its own goroutine with a bounded queue, so a slow or
// unreachable receiver never holds up ingestion.
package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ProtoUDP = "udp"
	ProtoTCP = "tcp"

	dialTimeout  = 5 * time.Second
	writeTimeout = 5 * time.Second
	// After a failed dial, messages fail fast instead of each waiting for
	// a new dial timeout.
	redialDelay = 5 * time.Second
)

type Config struct {
	Enabled  bool
	Address  string
	Protocol string
}

type Status struct {
	Sent        uint64     `json:"sent"`
	Dropped     uint64     `json:"dropped"`
	Failed      uint64     `json:"failed"`
	LastError   string     `json:"last_error"`
	LastErrorAt *time.Time `json:"last_error_at"`
}

type Forwarder struct {
	queue chan string

	mu        sync.Mutex
	cfg       Config
	lastErr   string
	lastErrAt time.Time

	sent, dropped, failed atomic.Uint64

	// Owned by the Run goroutine.
	conn     net.Conn
	connCfg  Config
	nextDial time.Time
}

func New() *Forwarder {
	return &Forwarder{queue: make(chan string, 10000)}
}

// Configure replaces the configuration; an open connection to a previous
// target is closed by the worker before the next message.
func (f *Forwarder) Configure(cfg Config) {
	f.mu.Lock()
	f.cfg = cfg
	f.mu.Unlock()
}

func (f *Forwarder) config() Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

// Send queues a message; it never blocks and drops the message when the
// queue is full.
func (f *Forwarder) Send(msg string) {
	select {
	case f.queue <- msg:
	default:
		f.dropped.Add(1)
	}
}

func (f *Forwarder) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := Status{Sent: f.sent.Load(), Dropped: f.dropped.Load(), Failed: f.failed.Load(), LastError: f.lastErr}
	if !f.lastErrAt.IsZero() {
		t := f.lastErrAt
		s.LastErrorAt = &t
	}
	return s
}

func (f *Forwarder) setError(err error) {
	f.mu.Lock()
	f.lastErr = err.Error()
	f.lastErrAt = time.Now().UTC()
	f.mu.Unlock()
}

// Run sends queued messages until ctx is done.
func (f *Forwarder) Run(ctx context.Context) {
	defer f.closeConn()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-f.queue:
			if err := f.write(msg); err != nil {
				f.failed.Add(1)
				f.setError(err)
			} else {
				f.sent.Add(1)
			}
		}
	}
}

func (f *Forwarder) closeConn() {
	if f.conn != nil {
		f.conn.Close()
		f.conn = nil
	}
}

func (f *Forwarder) write(msg string) error {
	cfg := f.config()
	if cfg != f.connCfg {
		f.closeConn()
		f.connCfg = cfg
		f.nextDial = time.Time{}
	}
	if !cfg.Enabled {
		return fmt.Errorf("forwarding is disabled")
	}
	frame := Frame(cfg.Protocol, msg)
	// A broken TCP connection is often only noticed on write, so retry once
	// on a fresh connection.
	for attempt := 0; attempt < 2; attempt++ {
		if f.conn != nil && cfg.Protocol == ProtoTCP && !peerOpen(f.conn) {
			f.closeConn()
		}
		if f.conn == nil {
			if time.Now().Before(f.nextDial) {
				return fmt.Errorf("not connected to %s (retrying shortly)", cfg.Address)
			}
			conn, err := net.DialTimeout(cfg.Protocol, cfg.Address, dialTimeout)
			if err != nil {
				f.nextDial = time.Now().Add(redialDelay)
				return err
			}
			f.conn = conn
		}
		f.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err := f.conn.Write(frame)
		if err == nil {
			return nil
		}
		f.closeConn()
		if attempt == 1 {
			return err
		}
	}
	return nil
}

// peerOpen reports whether the receiver still has the TCP connection open.
// A write to a connection the peer has closed usually succeeds and the data
// is silently lost, so this is checked before writing. Syslog receivers
// never send anything, so any read result other than a timeout means the
// connection is gone.
func peerOpen(conn net.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})
	var b [1]byte
	_, err := conn.Read(b[:])
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Frame encodes a message for the protocol: one message per datagram for
// UDP, octet counting (RFC 6587) for TCP.
func Frame(protocol, msg string) []byte {
	msg = strings.TrimRight(msg, "\r\n")
	if protocol == ProtoTCP {
		return []byte(fmt.Sprintf("%d %s", len(msg), msg))
	}
	return []byte(msg)
}

// Test sends one message synchronously on a separate connection. UDP
// cannot detect a missing receiver, so success only means it was sent.
func Test(cfg Config, msg string) error {
	conn, err := net.DialTimeout(cfg.Protocol, cfg.Address, dialTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = conn.Write(Frame(cfg.Protocol, msg))
	return err
}
