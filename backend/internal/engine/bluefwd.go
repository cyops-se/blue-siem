package engine

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// blue-fwd (../blue-fwd) forwards Windows event logs as syslog. With RFC 5424
// it adds [win@32473 channel=.. provider=.. eventId=.. recordId=..
// subscription=..]; the payload is JSON (default), the event XML or the
// rendered message text.

const blueFwdSDID = "win@32473"

// Windows event keywords for the Security log.
const (
	keywordAuditFailure = 0x0010000000000000
	keywordAuditSuccess = 0x0020000000000000
)

var blueFwdSD = map[string]string{
	"channel":      "channel",
	"provider":     "provider",
	"eventId":      "event_id",
	"recordId":     "record_id",
	"subscription": "subscription",
}

// System fields of the JSON payload and their field names.
var blueFwdSystem = map[string]string{
	"TimeCreated": "time_created",
	"Computer":    "computer",
	"Channel":     "channel",
	"Provider":    "provider",
	"EventID":     "event_id",
	"RecordID":    "record_id",
	"Level":       "level",
	"Task":        "task",
	"Opcode":      "opcode",
	"Keywords":    "keywords",
	"ProcessID":   "process_id",
	"ThreadID":    "thread_id",
	"UserID":      "user_sid",
}

// Common EventData names copied to the field names other decoders use, so
// that the same rules apply. The first non-empty source wins.
var blueFwdAliases = []struct {
	field   string
	sources []string
}{
	{"src_ip", []string{"SourceIp", "IpAddress"}},
	{"dst_ip", []string{"DestinationIp"}},
	{"src_port", []string{"SourcePort", "IpPort"}},
	{"dst_port", []string{"DestinationPort"}},
	{"proto", []string{"Protocol"}},
	{"user", []string{"TargetUserName", "User"}},
	{"image", []string{"Image", "NewProcessName"}},
	{"command", []string{"CommandLine"}},
}

// ParseBlueFwd decodes a blue-fwd message. It returns false unless the
// message carries blue-fwd structured data, a Windows event payload (JSON
// or XML) or is a blue-fwd test message.
func ParseBlueFwd(msgID string, sd map[string]map[string]string, msg string) (map[string]string, []string, bool) {
	fields := map[string]string{}
	var tags []string
	recognised := false

	for k, v := range sd[blueFwdSDID] {
		if name, ok := blueFwdSD[k]; ok && v != "" {
			fields[name] = v
			recognised = true
		}
	}

	trimmed := strings.TrimSpace(msg)
	switch {
	case strings.HasPrefix(trimmed, "{"):
		recognised = parseBlueFwdJSON(trimmed, fields) || recognised
	case strings.HasPrefix(trimmed, "<Event"):
		recognised = parseBlueFwdXML(trimmed, fields) || recognised
	}
	if msgID == "TEST" && !recognised {
		recognised = true
		tags = append(tags, "test")
	}
	if !recognised {
		return nil, nil, false
	}

	for _, a := range blueFwdAliases {
		if fields[a.field] != "" {
			continue
		}
		for _, src := range a.sources {
			if v := fields[src]; v != "" && v != "-" {
				fields[a.field] = v
				break
			}
		}
	}

	channel := strings.ToLower(fields["channel"])
	switch {
	case strings.Contains(channel, "sysmon"):
		tags = append(tags, "sysmon")
	case strings.Contains(channel, "powershell"):
		tags = append(tags, "powershell")
	case channel == "security" || channel == "system" || channel == "application":
		tags = append(tags, channel)
	}
	if kw, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(fields["keywords"]), "0x"), 16, 64); err == nil {
		if kw&keywordAuditFailure != 0 {
			tags = append(tags, "audit_failure")
		}
		if kw&keywordAuditSuccess != 0 {
			tags = append(tags, "audit_success")
		}
	}
	return fields, tags, true
}

// parseBlueFwdJSON reads the JSON payload: system fields under normalised
// names, EventData and UserData entries under their own names (nested
// UserData joined with "_").
func parseBlueFwdJSON(s string, fields map[string]string) bool {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return false
	}
	if _, ok := obj["EventID"]; !ok {
		return false
	}
	for k, v := range obj {
		switch {
		case k == "EventData" || k == "UserData":
			flattenJSON("", v, fields)
		case blueFwdSystem[k] != "":
			if str := jsonString(v); str != "" {
				fields[blueFwdSystem[k]] = str
			}
		}
	}
	return true
}

func flattenJSON(prefix string, v any, fields map[string]string) {
	if m, ok := v.(map[string]any); ok {
		for k, child := range m {
			name := k
			if prefix != "" {
				name = prefix + "_" + k
			}
			flattenJSON(name, child, fields)
		}
		return
	}
	if prefix != "" {
		if str := jsonString(v); str != "" {
			if _, exists := fields[prefix]; !exists {
				fields[prefix] = str
			}
		}
	}
}

func jsonString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

type winEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID       string `xml:"EventID"`
		Level         string `xml:"Level"`
		Task          string `xml:"Task"`
		Opcode        string `xml:"Opcode"`
		Keywords      string `xml:"Keywords"`
		EventRecordID string `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Execution struct {
			ProcessID string `xml:"ProcessID,attr"`
			ThreadID  string `xml:"ThreadID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"UserData"`
}

// parseBlueFwdXML reads the raw event XML payload.
func parseBlueFwdXML(s string, fields map[string]string) bool {
	var ev winEvent
	if err := xml.Unmarshal([]byte(s), &ev); err != nil || ev.System.EventID == "" {
		return false
	}
	sys := ev.System
	for name, v := range map[string]string{
		"time_created": sys.TimeCreated.SystemTime, "computer": sys.Computer, "channel": sys.Channel,
		"provider": sys.Provider.Name, "event_id": sys.EventID, "record_id": sys.EventRecordID,
		"level": sys.Level, "task": sys.Task, "opcode": sys.Opcode, "keywords": sys.Keywords,
		"process_id": sys.Execution.ProcessID, "thread_id": sys.Execution.ThreadID, "user_sid": sys.Security.UserID,
	} {
		if v != "" {
			fields[name] = strings.TrimSpace(v)
		}
	}
	for i, d := range ev.EventData.Data {
		name := d.Name
		if name == "" {
			name = fmt.Sprintf("Data%d", i)
		}
		if _, exists := fields[name]; !exists {
			fields[name] = d.Value
		}
	}
	flattenXML(ev.UserData.Inner, fields)
	return true
}

// flattenXML adds the leaf elements of UserData, named by their path below
// the first element joined with "_".
func flattenXML(inner []byte, fields map[string]string) {
	dec := xml.NewDecoder(bytes.NewReader(inner))
	var path []string
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if len(path) > 1 {
				name := strings.Join(path[1:], "_")
				if v := strings.TrimSpace(text.String()); v != "" {
					if _, exists := fields[name]; !exists {
						fields[name] = v
					}
				}
			}
			text.Reset()
			path = path[:len(path)-1]
		}
	}
}
