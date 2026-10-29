package engine

import (
	"regexp"
	"strings"
)

var kernelTSRe = regexp.MustCompile(`^\[\s*\d+\.\d+\]\s*`)

// Normalised names for the most common netfilter keys so that rules can use
// the same field names as other decoders (src_ip, dst_port, ...).
var iptablesKeys = map[string]string{
	"IN":     "in_iface",
	"OUT":    "out_iface",
	"SRC":    "src_ip",
	"DST":    "dst_ip",
	"SPT":    "src_port",
	"DPT":    "dst_port",
	"PROTO":  "proto",
	"MAC":    "mac",
	"LEN":    "len",
	"TTL":    "ttl",
	"PHYSIN": "phys_in",
}

var actionWords = []string{"DROP", "REJECT", "ACCEPT", "DENY", "BLOCK", "ALLOW", "LOG"}

// ParseIPTables decodes a netfilter LOG target line such as
//
//	[1234.5678] BLACK DROP: IN=eth0 OUT= MAC=.. SRC=1.2.3.4 DST=10.0.0.1 ... PROTO=TCP SPT=4000 DPT=22 SYN
//
// It returns false if the message does not look like an iptables log.
func ParseIPTables(msg string) (map[string]string, bool) {
	idx := strings.Index(msg, "IN=")
	if idx < 0 || (idx > 0 && msg[idx-1] != ' ' && msg[idx-1] != ':' && msg[idx-1] != ']') {
		return nil, false
	}
	if !strings.Contains(msg[idx:], " SRC=") || !strings.Contains(msg[idx:], " DST=") {
		return nil, false
	}

	fields := map[string]string{}
	prefix := strings.TrimSpace(kernelTSRe.ReplaceAllString(msg[:idx], ""))
	fields["prefix"] = prefix

	var flags []string
	for _, tok := range strings.Fields(msg[idx:]) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			flags = append(flags, tok)
			continue
		}
		if name, known := iptablesKeys[k]; known {
			k = name
		} else {
			k = strings.ToLower(k)
		}
		fields[k] = v
	}
	if len(flags) > 0 {
		fields["flags"] = strings.Join(flags, " ")
	}

	words := prefixWords(prefix)
	for _, w := range words {
		for _, a := range actionWords {
			if w == a {
				fields["action"] = a
				break
			}
		}
		if fields["action"] != "" {
			break
		}
	}
	switch {
	case fields["in_iface"] != "" && fields["out_iface"] != "":
		fields["direction"] = "forward"
	case fields["in_iface"] != "":
		fields["direction"] = "inbound"
	case fields["out_iface"] != "":
		fields["direction"] = "outbound"
	}
	return fields, true
}

// prefixWords splits a log prefix such as "[BLACK-DROP] " into upper case
// words.
func prefixWords(prefix string) []string {
	return strings.FieldsFunc(strings.ToUpper(prefix), func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	})
}

// prefixClass returns WHITE, BLACK or GREY if the log prefix names one.
func prefixClass(prefix string) string {
	for _, w := range prefixWords(prefix) {
		switch w {
		case "WHITE", "WHITELIST", "ALLOWLIST":
			return "WHITE"
		case "BLACK", "BLACKLIST", "BLOCKLIST":
			return "BLACK"
		case "GREY", "GRAY", "GREYLIST", "GRAYLIST":
			return "GREY"
		}
	}
	return ""
}
