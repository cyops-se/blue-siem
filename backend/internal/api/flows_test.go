package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"blue-siem/internal/engine"
	"blue-siem/internal/models"
	"blue-siem/internal/store"
)

func TestFlows(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	eng := engine.New(db)
	if err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	const fw = "<4>Oct 29 10:00:00 fw kernel: %s IN=eth0 OUT= SRC=%s DST=10.0.0.1 PROTO=TCP SPT=%d DPT=%d SYN"
	msgs := []string{
		fmt.Sprintf(fw, "BLACK DROP:", "8.8.8.8", 1000, 22),
		fmt.Sprintf(fw, "BLACK DROP:", "8.8.8.8", 1000, 22),
		fmt.Sprintf(fw, "BLACK DROP:", "8.8.8.8", 1001, 22),
		fmt.Sprintf(fw, "GREY ACCEPT:", "9.9.9.9", 2000, 443),
		fmt.Sprintf(fw, "WHITE ACCEPT:", "192.168.1.5", 3000, 80),
		"<38>Oct 29 10:00:00 web sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
	}
	for _, m := range msgs {
		if _, _, err := eng.Process(m, "10.0.0.254"); err != nil {
			t.Fatal(err)
		}
	}
	h := NewRouter(db, eng, Info{}, fstest.MapFS{})

	type resp struct {
		Items   []flowRow      `json:"items"`
		Total   int64          `json:"total"`
		Classes []flowClassRow `json:"classes"`
	}
	get := func(url string) resp {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", url, rec.Code, rec.Body)
		}
		var out resp
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	all := get("/api/flows")
	if all.Total != 4 || len(all.Items) != 4 {
		t.Fatalf("total=%d items=%+v", all.Total, all.Items)
	}
	top := all.Items[0]
	if top.Class != models.ClassBlack || top.Count != 2 || top.SrcPort != "1000" || top.DstPort != "22" ||
		top.Proto != "TCP" || top.Actions != "DROP" || top.MaxCrit != 9 || top.LastSeen == "" || top.LastSeen[10] != 'T' {
		t.Errorf("top flow %+v", top)
	}
	classes := map[string]flowClassRow{}
	for _, c := range all.Classes {
		classes[c.Class] = c
	}
	if c := classes[models.ClassBlack]; c.Flows != 2 || c.Events != 3 {
		t.Errorf("black summary %+v", c)
	}

	noSrcPort := get("/api/flows?group=src_ip,dst_ip,dst_port,proto&class=black")
	if noSrcPort.Total != 1 || noSrcPort.Items[0].Count != 3 || noSrcPort.Items[0].SrcPort != "" {
		t.Errorf("grouped without src_port: %+v", noSrcPort)
	}
	if len(noSrcPort.Classes) != 3 {
		t.Errorf("class summary should ignore class filter: %+v", noSrcPort.Classes)
	}

	byPort := get("/api/flows?sort=dst_port&order=asc")
	if byPort.Items[0].DstPort != "22" || byPort.Items[len(byPort.Items)-1].DstPort != "443" {
		t.Errorf("sort by dst_port: %+v", byPort.Items)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/events?f.src_ip=8.8.8.8&f.src_port=1000", nil))
	var evs struct{ Total int64 }
	json.Unmarshal(rec.Body.Bytes(), &evs)
	if evs.Total != 2 {
		t.Errorf("field filter: total=%d", evs.Total)
	}
}

func TestLearningMode(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	eng := engine.New(db)
	if err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	h := NewRouter(db, eng, Info{}, fstest.MapFS{})
	do := func(method, url, body string) []byte {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, url, strings.NewReader(body)))
		if rec.Code >= 300 {
			t.Fatalf("%s %s: %d %s", method, url, rec.Code, rec.Body)
		}
		return rec.Body.Bytes()
	}

	// A partial update only changes learning_mode.
	var set settingsDTO
	json.Unmarshal(do("PUT", "/api/settings", `{"learning_mode": true}`), &set)
	if !set.LearningMode || set.AlarmThreshold != 7 || set.RetentionDays != 30 {
		t.Fatalf("settings %+v", set)
	}

	grey := "<4>Oct 29 10:00:00 fw kernel: GREY ACCEPT: IN=eth0 OUT= SRC=9.9.9.9 DST=10.0.0.1 PROTO=TCP SPT=2000 DPT=3389 SYN"
	ssh := "<38>Oct 29 10:00:00 web sshd[1]: Accepted publickey for root from 1.2.3.4 port 22 ssh2"
	raw, _ := json.Marshal(map[string]string{"raw": grey + "\n" + grey + "\n" + ssh})
	var ing map[string]int
	json.Unmarshal(do("POST", "/api/ingest", string(raw)), &ing)
	if ing["flow_only"] != 2 || ing["events"] != 1 || ing["alarms"] != 1 {
		t.Errorf("ingest %v", ing)
	}

	var events int64
	db.Model(&models.Event{}).Where("json_extract(fields, '$.class') IS NOT NULL").Count(&events)
	if events != 0 {
		t.Errorf("%d iptables events stored in learning mode", events)
	}
	var flows struct{ Items []flowRow }
	json.Unmarshal(do("GET", "/api/flows", ""), &flows)
	if len(flows.Items) != 1 || flows.Items[0].Count != 2 || flows.Items[0].MaxCrit != 8 {
		t.Errorf("flows %+v", flows.Items)
	}

	raw, _ = json.Marshal(map[string]string{"raw": grey})
	var res []engine.Result
	json.Unmarshal(do("POST", "/api/test", string(raw)), &res)
	if len(res) != 1 || !res[0].FlowOnly || res[0].Alarm {
		t.Errorf("test result %+v", res)
	}

	do("PUT", "/api/settings", `{"learning_mode": false}`)
	json.Unmarshal(do("POST", "/api/ingest", string(raw)), &ing)
	if ing["events"] != 1 || ing["alarms"] != 1 || ing["flow_only"] != 0 {
		t.Errorf("ingest after learning %v", ing)
	}
	json.Unmarshal(do("GET", "/api/flows", ""), &flows)
	if flows.Items[0].Count != 3 {
		t.Errorf("flow count after learning %+v", flows.Items)
	}

	do("DELETE", "/api/flows", "")
	json.Unmarshal(do("GET", "/api/flows", ""), &flows)
	if len(flows.Items) != 0 {
		t.Errorf("flows not cleared: %+v", flows.Items)
	}
}

func TestFlowsPerSource(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	eng := engine.New(db)
	if err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	const fw = "<4>Oct 29 10:00:00 %s kernel: %s IN=eth0 OUT= SRC=8.8.8.8 DST=10.0.0.1 PROTO=TCP SPT=1000 DPT=22 SYN"
	for _, m := range []string{
		fmt.Sprintf(fw, "fw1", "BLACK DROP:"),
		fmt.Sprintf(fw, "fw1", "BLACK DROP:"),
		fmt.Sprintf(fw, "fw2", "BLACK DROP:"),
		fmt.Sprintf(fw, "fw2", "GREY ACCEPT:"),
		fmt.Sprintf(fw, "fw2", "GREY ACCEPT:"),
		fmt.Sprintf(fw, "fw2", "GREY ACCEPT:"),
	} {
		if _, _, err := eng.Process(m, "10.0.0.254"); err != nil {
			t.Fatal(err)
		}
	}
	h := NewRouter(db, eng, Info{}, fstest.MapFS{})
	type resp struct {
		Items   []flowRow       `json:"items"`
		Classes []flowClassRow  `json:"classes"`
		Sources []flowSourceRow `json:"sources"`
	}
	get := func(url string) resp {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", url, rec.Code, rec.Body)
		}
		var out resp
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	all := get("/api/flows")
	if len(all.Items) != 3 || all.Items[0].Hostname != "fw2" || all.Items[0].Count != 3 {
		t.Errorf("items %+v", all.Items)
	}
	src := map[string]flowSourceRow{}
	for _, s := range all.Sources {
		src[s.Hostname] = s
	}
	if src["fw1"].Flows != 1 || src["fw1"].Events != 2 || src["fw2"].Flows != 2 || src["fw2"].Events != 4 {
		t.Errorf("sources %+v", all.Sources)
	}

	// Without hostname grouped, both sources merge into one BLACK flow, but
	// the source summary still counts per source.
	merged := get("/api/flows?group=src_ip,dst_ip,dst_port&class=BLACK")
	if len(merged.Items) != 1 || merged.Items[0].Count != 3 || merged.Items[0].Hostname != "" {
		t.Errorf("merged %+v", merged.Items)
	}
	if len(merged.Sources) != 2 {
		t.Errorf("merged sources %+v", merged.Sources)
	}
	if m := merged.Items[0]; m.NHostname != 2 || m.SHostname != "fw1,fw2" || m.NSrcIP != 1 || m.Proto != "TCP" || m.NProto != 1 {
		t.Errorf("ungrouped columns %+v", m)
	}

	// Sorting on an ungrouped field orders by its number of distinct values.
	spread := get("/api/flows?group=src_ip&sort=hostname&order=desc")
	if len(spread.Items) != 2 || spread.Items[0].NHostname != 2 || spread.Items[0].Class != "BLACK" {
		t.Errorf("sort by spread %+v", spread.Items)
	}

	one := get("/api/flows?hostname=fw1")
	if len(one.Items) != 1 || one.Items[0].Hostname != "fw1" || len(one.Classes) != 1 || len(one.Sources) != 2 {
		t.Errorf("hostname filter %+v", one)
	}
}
