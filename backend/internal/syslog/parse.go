// Package syslog parses RFC 3164 (BSD) and RFC 5424 syslog messages and
// receives them over UDP and TCP.
package syslog

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	FormatRFC5424 = "rfc5424"
	FormatRFC3164 = "rfc3164"
	FormatRaw     = "raw"
)

type Message struct {
	Facility  int
	Severity  int
	Timestamp time.Time
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
	Message   string
	Format    string
}

var tagRe = regexp.MustCompile(`^([^\s\[\]:]+)(?:\[([^\]]*)\])?:\s?(.*)$`)

// Parse is lenient: anything it cannot interpret ends up in Message.
// now is used for missing timestamps and for the year of RFC 3164 timestamps.
func Parse(raw string, now time.Time) Message {
	s := strings.TrimRight(raw, "\r\n\x00")
	m := Message{Facility: 1, Severity: 5, Timestamp: now, Format: FormatRaw}

	if pri, rest, ok := parsePRI(s); ok {
		m.Facility, m.Severity = pri/8, pri%8
		s = rest
		m.Format = FormatRFC3164
	}

	if strings.HasPrefix(s, "1 ") && m.Format == FormatRFC3164 {
		if parse5424(s[2:], &m) {
			m.Format = FormatRFC5424
			return m
		}
	}
	parse3164(s, now, &m)
	return m
}

func parsePRI(s string) (int, string, bool) {
	if len(s) < 3 || s[0] != '<' {
		return 0, s, false
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 4 {
		return 0, s, false
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return 0, s, false
	}
	return pri, s[end+1:], true
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func parse5424(s string, m *Message) bool {
	parts := strings.SplitN(s, " ", 6)
	if len(parts) < 5 {
		return false
	}
	if ts := nilValue(parts[0]); ts != "" {
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return false
		}
		m.Timestamp = t
	}
	m.Hostname = nilValue(parts[1])
	m.AppName = nilValue(parts[2])
	m.ProcID = nilValue(parts[3])
	m.MsgID = nilValue(parts[4])
	rest := ""
	if len(parts) == 6 {
		rest = parts[5]
	}
	rest = skipStructuredData(rest)
	m.Message = strings.TrimPrefix(strings.TrimSpace(rest), string(rune(0xFEFF)))
	return true
}

// skipStructuredData drops "-" or one or more [id k="v"] elements.
func skipStructuredData(s string) string {
	if strings.HasPrefix(s, "-") {
		return s[1:]
	}
	i := 0
	for i < len(s) && s[i] == '[' {
		inQuote := false
		for i++; i < len(s); i++ {
			c := s[i]
			if c == '\\' && inQuote {
				i++
				continue
			}
			if c == '"' {
				inQuote = !inQuote
			} else if c == ']' && !inQuote {
				i++
				break
			}
		}
	}
	return s[i:]
}

var bsdLayouts = []string{"Jan _2 15:04:05", "Jan 02 15:04:05"}

func parse3164(s string, now time.Time, m *Message) {
	s = strings.TrimLeft(s, " ")

	// Timestamp: classic "Mmm dd hh:mm:ss" or an RFC 3339 timestamp, which
	// rsyslog and syslog-ng commonly send.
	if len(s) >= 15 {
		for _, layout := range bsdLayouts {
			if t, err := time.ParseInLocation(layout, s[:15], time.Local); err == nil {
				t = t.AddDate(now.Year(), 0, 0)
				if t.After(now.Add(24 * time.Hour)) {
					t = t.AddDate(-1, 0, 0)
				}
				m.Timestamp = t
				s = strings.TrimLeft(s[15:], " ")
				break
			}
		}
	}
	if first, rest, found := strings.Cut(s, " "); found && len(first) >= 19 && first[4] == '-' {
		if t, err := time.Parse(time.RFC3339Nano, first); err == nil {
			m.Timestamp = t
			s = rest
		}
	}

	// Either "host tag[pid]: msg" or just "tag[pid]: msg".
	if sm := tagRe.FindStringSubmatch(s); sm != nil && !strings.Contains(sm[1], ".") {
		m.AppName, m.ProcID, m.Message = sm[1], sm[2], sm[3]
		return
	}
	if host, rest, found := strings.Cut(s, " "); found && host != "" && !strings.HasSuffix(host, ":") {
		if sm := tagRe.FindStringSubmatch(rest); sm != nil {
			m.Hostname = host
			m.AppName, m.ProcID, m.Message = sm[1], sm[2], sm[3]
			return
		}
		if m.Format == FormatRFC3164 {
			m.Hostname = host
			m.Message = rest
			return
		}
	}
	m.Message = s
}
