package engine

import (
	"fmt"
	"testing"
)

// winMsg builds a blue-fwd RFC 5424 message with a JSON payload.
func winMsg(channel, provider string, eventID int, keywords, eventData string) string {
	return fmt.Sprintf(`<134>1 2026-11-02T08:00:00Z WS01 blue-fwd - %d [win@32473 channel=%q provider=%q eventId="%d" recordId="1" subscription="test"] `+
		`{"Computer":"WS01","Channel":%q,"Provider":%q,"EventID":%d,"RecordID":1,"Level":"Information","Keywords":%q,"EventData":{%s}}`,
		eventID, channel, provider, eventID, channel, provider, eventID, keywords, eventData)
}

func sysmonNet(dstIP, dstPort, initiated string) string {
	return winMsg("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 3, "0x8000000000000000",
		fmt.Sprintf(`"Image":"C:/Windows/System32/curl.exe","Protocol":"tcp","Initiated":%q,"SourceIp":"10.0.0.5","SourcePort":"50123","DestinationIp":%q,"DestinationPort":%q`,
			initiated, dstIP, dstPort))
}

func TestWindowsRules(t *testing.T) {
	e := newEngine(t) // blacklists 198.51.100.0/24
	const security, auditing = "Security", "Microsoft-Windows-Security-Auditing"
	tests := []struct {
		name, raw, rule string
		crit            int
		alarm           bool
	}{
		{"failed logon", winMsg(security, auditing, 4625, "0x8010000000000000", `"TargetUserName":"administrator","IpAddress":"203.0.113.7"`),
			"Windows: failed logon (4625)", 5, false},
		{"failed logon from blacklisted address", winMsg(security, auditing, 4625, "0x8010000000000000", `"TargetUserName":"administrator","IpAddress":"198.51.100.7"`),
			"Windows: blacklisted address", 9, true},
		{"account locked out", winMsg(security, auditing, 4740, "0x8020000000000000", `"TargetUserName":"bob"`),
			"Windows: account locked out (4740)", 7, true},
		{"security log cleared", winMsg(security, "Microsoft-Windows-Eventlog", 1102, "0x4020000000000000", ``),
			"Windows: event log cleared (1102/104)", 8, true},
		{"system log cleared", winMsg("System", "Microsoft-Windows-Eventlog", 104, "0x8000000000000000", ``),
			"Windows: event log cleared (1102/104)", 8, true},
		{"user created", winMsg(security, auditing, 4720, "0x8020000000000000", `"TargetUserName":"backdoor"`),
			"Windows: user account created (4720)", 7, true},
		{"added to group", winMsg(security, auditing, 4732, "0x8020000000000000", `"TargetUserName":"Administrators","MemberSid":"S-1-5-21-9"`),
			"Windows: member added to security group (4728/4732/4756)", 7, true},
		{"service installed", winMsg("System", "Service Control Manager", 7045, "0x8080000000000000", `"ServiceName":"evil","ImagePath":"C:/x.exe"`),
			"Windows: service installed (7045/4697)", 6, false},
		{"scheduled task", winMsg(security, auditing, 4698, "0x8020000000000000", `"TaskName":"/upd"`),
			"Windows: scheduled task created (4698)", 6, false},
		{"sysmon to blacklisted address", sysmonNet("198.51.100.20", "443", "true"), "Windows: blacklisted address", 9, true},
		{"sysmon unusual port", sysmonNet("203.0.113.9", "4444", "true"), "Sysmon: outgoing connection to unusual port", 4, false},
		{"sysmon https", sysmonNet("203.0.113.9", "443", "true"), "", 0, false},
		{"sysmon inbound", sysmonNet("10.0.0.5", "4444", "false"), "", 0, false},
		{"other security event", winMsg(security, auditing, 4624, "0x8020000000000000", `"TargetUserName":"erik","LogonType":"2"`), "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := e.Analyze(tt.raw, "10.0.0.1")
			if r.Event.Decoder != "blue-fwd" {
				t.Fatalf("decoder %q", r.Event.Decoder)
			}
			if r.Event.Criticality != tt.crit || r.TopRule != tt.rule || r.Alarm != tt.alarm {
				t.Errorf("crit=%d top=%q alarm=%v matched=%v fields=%v", r.Event.Criticality, r.TopRule, r.Alarm, r.Matched, r.Event.Fields)
			}
		})
	}
}
