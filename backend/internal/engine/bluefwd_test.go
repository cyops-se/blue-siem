package engine

import "testing"

// Messages as blue-fwd sends them (without the octet-counting prefix).
const (
	blueFwdSysmonNet   = `<134>1 2026-10-29T12:13:41.484071Z WS01 blue-fwd - 3 [win@32473 channel="Microsoft-Windows-Sysmon/Operational" provider="Microsoft-Windows-Sysmon" eventId="3" recordId="5512" subscription="Sysmon"] {"TimeCreated":"2026-10-29T12:13:41.4840710Z","Computer":"WS01","Channel":"Microsoft-Windows-Sysmon/Operational","Provider":"Microsoft-Windows-Sysmon","EventID":3,"RecordID":5512,"Level":"Information","Task":3,"Opcode":0,"Keywords":"0x8000000000000000","ProcessID":3040,"ThreadID":4120,"UserID":"S-1-5-18","EventData":{"RuleName":"-","UtcTime":"2026-10-29 12:13:41.470","ProcessId":"5012","Image":"C:\\Windows\\System32\\cmd.exe","User":"WS01\\erik","Protocol":"tcp","Initiated":"true","SourceIp":"10.0.0.5","SourcePort":"50123","DestinationIp":"203.0.113.9","DestinationPort":"4444"}}`
	blueFwdLogonFailed = `<133>Oct 29 13:13:41 DC01 bluefwd: {"Computer":"DC01","Channel":"Security","Provider":"Microsoft-Windows-Security-Auditing","EventID":4625,"RecordID":991,"Level":"Information","Keywords":"0x8010000000000000","EventData":{"TargetUserName":"administrator","LogonType":"3","IpAddress":"198.51.100.7","IpPort":"0"},"UserData":null}`
	blueFwdXML         = `<134>1 2026-10-29T12:13:41Z WS01 blue-fwd - 104 [win@32473 channel="System" eventId="104"] <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>104</EventID><Level>4</Level><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2026-10-29T12:13:41.000Z"/><EventRecordID>77</EventRecordID><Execution ProcessID="1388" ThreadID="1400"/><Channel>System</Channel><Computer>WS01</Computer><Security UserID="S-1-5-21-1"/></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>erik</SubjectUserName><Channel>Security</Channel></LogFileCleared></UserData></Event>`
	blueFwdText        = `<134>1 2026-10-29T12:13:41Z WS01 blue-fwd - 4104 [win@32473 channel="Microsoft-Windows-PowerShell/Operational" provider="Microsoft-Windows-PowerShell" eventId="4104" recordId="12" subscription="PowerShell"] Creating Scriptblock text (1 of 1): Invoke-WebRequest http://x`
	blueFwdTest        = `<134>1 2026-11-02T08:00:00.000000Z WS01 blue-fwd - TEST - blue-fwd test message from WS01 at 2026-11-02T09:00:00+01:00`
)

func TestBlueFwdDecoder(t *testing.T) {
	e := newEngine(t)
	tests := []struct {
		name, raw string
		fields    map[string]string
		tags      []string
	}{
		{"sysmon network json", blueFwdSysmonNet, map[string]string{
			"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "3", "record_id": "5512", "subscription": "Sysmon",
			"computer": "WS01", "user_sid": "S-1-5-18", "Image": `C:\Windows\System32\cmd.exe`, "image": `C:\Windows\System32\cmd.exe`,
			"src_ip": "10.0.0.5", "src_port": "50123", "dst_ip": "203.0.113.9", "dst_port": "4444", "proto": "tcp", "user": `WS01\erik`,
		}, []string{"windows", "bluefwd", "sysmon"}},
		{"security logon failure rfc3164", blueFwdLogonFailed, map[string]string{
			"channel": "Security", "event_id": "4625", "TargetUserName": "administrator", "user": "administrator",
			"src_ip": "198.51.100.7", "LogonType": "3",
		}, []string{"windows", "security", "audit_failure"}},
		{"xml payload", blueFwdXML, map[string]string{
			"channel": "System", "event_id": "104", "provider": "Microsoft-Windows-Eventlog", "process_id": "1388",
			"user_sid": "S-1-5-21-1", "SubjectUserName": "erik", "Channel": "Security",
		}, []string{"windows", "system"}},
		{"message payload", blueFwdText, map[string]string{
			"channel": "Microsoft-Windows-PowerShell/Operational", "event_id": "4104", "subscription": "PowerShell",
		}, []string{"windows", "powershell"}},
		{"test message", blueFwdTest, map[string]string{}, []string{"bluefwd", "test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := e.Analyze(tt.raw, "10.0.0.1").Event
			if ev.Decoder != "blue-fwd" {
				t.Fatalf("decoder %q, app %q, message %q", ev.Decoder, ev.AppName, ev.Message)
			}
			for k, v := range tt.fields {
				if ev.Fields[k] != v {
					t.Errorf("%s = %q, want %q", k, ev.Fields[k], v)
				}
			}
			for _, tag := range tt.tags {
				if !ev.Tags.Has(tag) {
					t.Errorf("tags %v missing %s", ev.Tags, tag)
				}
			}
		})
	}

	// Without blue-fwd data the decoder does not claim the message, even
	// from an app called blue-fwd.
	if ev := e.Analyze("<134>1 2026-10-29T12:13:41Z WS01 blue-fwd - - - hello", "10.0.0.1").Event; ev.Decoder == "blue-fwd" {
		t.Errorf("plain message decoded: %+v", ev.Fields)
	}
	if ev := e.Analyze("<38>Oct 29 10:00:00 web sshd[1]: Accepted publickey for root from 1.2.3.4 port 22 ssh2", "").Event; ev.Decoder != "sshd-accepted" {
		t.Errorf("sshd decoded by %q", ev.Decoder)
	}
}
