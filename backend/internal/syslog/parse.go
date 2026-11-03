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
	// StructuredData holds the RFC 5424 SD elements: SD-ID -> param -> value.
	StructuredData map[string]map[string]string
	Message        string
	Format         string
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

// WithSeverity returns raw with its PRI set to the given facility and
// severity, leaving the rest of the message untouched. A message without a
// PRI gets one prepended.
func WithSeverity(raw string, facility, severity int) string {
	s := strings.TrimRight(raw, "\r\n\x00")
	if _, rest, ok := parsePRI(s); ok {
		s = rest
	}
	return "<" + strconv.Itoa(facility*8+severity) + ">" + s
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
	m.StructuredData, rest = parseStructuredData(rest)
	m.Message = strings.TrimPrefix(strings.TrimSpace(rest), string(rune(0xFEFF)))
	return true
}

// parseStructuredData reads "-" or one or more [id k="v" ...] elements and
// returns them with the rest of the message. Malformed data is skipped up to
// the end of the element rather than failing the whole message.
func parseStructuredData(s string) (map[string]map[string]string, string) {
	if strings.HasPrefix(s, "-") {
		return nil, s[1:]
	}
	var sd map[string]map[string]string
	i := 0
	for i < len(s) && s[i] == '[' {
		i++
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != ']' {
			i++
		}
		id := s[start:i]
		params := map[string]string{}
		for i < len(s) && s[i] != ']' {
			for i < len(s) && s[i] == ' ' {
				i++
			}
			start = i
			for i < len(s) && s[i] != '=' && s[i] != ']' && s[i] != ' ' {
				i++
			}
			name := s[start:i]
			if i+1 >= len(s) || s[i] != '=' || s[i+1] != '"' {
				// Not name="value": skip to the end of the element.
				for i < len(s) && s[i] != ']' {
					i++
				}
				break
			}
			i += 2
			var val strings.Builder
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte(`"\]`, s[i+1]) >= 0 {
					i++
				}
				val.WriteByte(s[i])
				i++
			}
			i++ // closing quote
			if name != "" {
				params[name] = val.String()
			}
		}
		i++ // closing bracket
		if id != "" {
			if sd == nil {
				sd = map[string]map[string]string{}
			}
			sd[id] = params
		}
	}
	if i > len(s) {
		i = len(s)
	}
	return sd, s[i:]
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
