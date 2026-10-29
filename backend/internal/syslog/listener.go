package syslog

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

// Handler receives a raw message and the sender's IP address.
type Handler func(raw, remoteIP string)

const maxMessageSize = 64 * 1024

// ListenUDP receives one message per datagram until ctx is cancelled.
func ListenUDP(ctx context.Context, addr string, h Handler) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	go func() {
		buf := make([]byte, maxMessageSize)
		for {
			n, remote, err := conn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("syslog udp: %v", err)
				continue
			}
			// A datagram may carry several newline separated messages.
			for _, line := range strings.Split(string(buf[:n]), "\n") {
				if strings.TrimSpace(line) != "" {
					h(line, hostOf(remote))
				}
			}
		}
	}()
	return nil
}

// ListenTCP accepts connections using either octet-counting (RFC 6587
// "123 <msg>") or newline delimited framing.
func ListenTCP(ctx context.Context, addr string, h Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("syslog tcp: %v", err)
				continue
			}
			go serveTCP(ctx, c, h)
		}
	}()
	return nil
}

func serveTCP(ctx context.Context, c net.Conn, h Handler) {
	defer c.Close()
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	remote := hostOf(c.RemoteAddr())
	r := bufio.NewReaderSize(c, maxMessageSize)
	for {
		msg, err := readFrame(r)
		if strings.TrimSpace(msg) != "" {
			h(msg, remote)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				log.Printf("syslog tcp %s: %v", remote, err)
			}
			return
		}
	}
}

func readFrame(r *bufio.Reader) (string, error) {
	first, err := r.Peek(1)
	if err != nil {
		return "", err
	}
	if first[0] >= '1' && first[0] <= '9' {
		lenStr, err := r.ReadString(' ')
		if err != nil {
			return "", err
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(lenStr))
		if convErr == nil && n > 0 && n <= maxMessageSize {
			buf := make([]byte, n)
			if _, err := io.ReadFull(r, buf); err != nil {
				return "", err
			}
			return string(buf), nil
		}
		// Not a length prefix after all; treat as a line.
		rest, err := r.ReadString('\n')
		return lenStr + rest, err
	}
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func hostOf(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
