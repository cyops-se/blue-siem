package forward

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	ModeOriginal = "original"
	ModeAlarm    = "alarm"

	// Alarm messages use facility 4 (security/authorization), independent of
	// the original message.
	alarmFacility = 4
)

// instanceRe limits instance names to what fits the RFC 5424 HOSTNAME field
// without escaping.
var instanceRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func ValidInstance(name string) bool {
	return instanceRe.MatchString(name)
}

// Alarm describes an alarm without any details about the traffic or host
// that caused it.
type Alarm struct {
	Instance    string
	Rule        string
	Criticality int
	Class       string
}

// AlarmMessage builds an RFC 5424 message announcing an alarm type from a
// blue-siem instance, e.g.
//
//	<34>1 2026-11-02T10:00:00Z siem01 blue-siem - alarm - Blue SIEM alarm: rule="Blacklisted traffic (BLACK)" criticality=9 class=BLACK
func AlarmMessage(a Alarm, severity int, now time.Time) string {
	instance := a.Instance
	if !ValidInstance(instance) {
		instance = "blue-siem"
	}
	msg := fmt.Sprintf("Blue SIEM alarm: rule=%s criticality=%d", quote(a.Rule), a.Criticality)
	if a.Class != "" {
		msg += " class=" + a.Class
	}
	return fmt.Sprintf("<%d>1 %s %s blue-siem - alarm - %s",
		alarmFacility*8+severity, now.UTC().Format(time.RFC3339), instance, msg)
}

// quote wraps a value in double quotes, escaping quotes and backslashes and
// dropping control characters so the message stays on one line.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
