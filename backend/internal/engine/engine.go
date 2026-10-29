// Package engine decodes syslog messages, classifies them, evaluates
// severity rules and raises alarms.
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"blue-siem/internal/models"
	"blue-siem/internal/store"
	"blue-siem/internal/syslog"
)

type compiledDecoder struct {
	models.Decoder
	app *regexp.Regexp
	re  *regexp.Regexp
}

type compiledCond struct {
	field  string
	re     *regexp.Regexp
	negate bool
}

type compiledRule struct {
	models.SeverityRule
	conds []compiledCond
}

type listNet struct {
	list    string
	net     *net.IPNet
	comment string
}

type Engine struct {
	db  *gorm.DB
	Hub *Hub

	mu        sync.RWMutex
	decoders  []compiledDecoder
	rules     []compiledRule
	nets      []listNet
	threshold int
	retention int
	learning  bool

	queue   chan inbound
	dropped atomic.Uint64
}

type inbound struct{ raw, remote string }

// Result is the outcome of analysing one message.
type Result struct {
	Event     models.Event `json:"event"`
	Matched   []string     `json:"matched_rules"`
	TopRule   string       `json:"top_rule"`
	Alarm     bool         `json:"alarm"`
	Threshold int          `json:"threshold"`
	// FlowOnly is set in learning mode for classified iptables traffic,
	// which is then only counted as a flow (no event, no alarm).
	FlowOnly bool `json:"flow_only"`
}

func New(db *gorm.DB) *Engine {
	return &Engine{db: db, Hub: NewHub(), queue: make(chan inbound, 10000)}
}

// Reload recompiles decoders, rules, IP lists and settings from the database.
// Entries with invalid patterns are skipped (the API validates on save).
func (e *Engine) Reload() error {
	var ds []models.Decoder
	if err := e.db.Where("enabled = ?", true).Order("priority, id").Find(&ds).Error; err != nil {
		return err
	}
	var rs []models.SeverityRule
	if err := e.db.Where("enabled = ?", true).Order("priority, id").Find(&rs).Error; err != nil {
		return err
	}
	var ls []models.IPListEntry
	if err := e.db.Find(&ls).Error; err != nil {
		return err
	}

	decoders := make([]compiledDecoder, 0, len(ds))
	for _, d := range ds {
		cd, err := CompileDecoder(d)
		if err != nil {
			log.Printf("decoder %q skipped: %v", d.Name, err)
			continue
		}
		decoders = append(decoders, cd)
	}
	rules := make([]compiledRule, 0, len(rs))
	for _, r := range rs {
		cr, err := CompileRule(r)
		if err != nil {
			log.Printf("rule %q skipped: %v", r.Name, err)
			continue
		}
		rules = append(rules, cr)
	}
	nets := make([]listNet, 0, len(ls))
	for _, l := range ls {
		_, n, err := net.ParseCIDR(l.CIDR)
		if err != nil {
			log.Printf("ip list entry %q skipped: %v", l.CIDR, err)
			continue
		}
		nets = append(nets, listNet{list: l.List, net: n, comment: l.Comment})
	}

	e.mu.Lock()
	e.decoders, e.rules, e.nets = decoders, rules, nets
	e.threshold = store.GetIntSetting(e.db, store.KeyAlarmThreshold)
	e.retention = store.GetIntSetting(e.db, store.KeyRetentionDays)
	e.learning = store.GetBoolSetting(e.db, store.KeyLearningMode)
	e.mu.Unlock()
	return nil
}

func CompileDecoder(d models.Decoder) (compiledDecoder, error) {
	cd := compiledDecoder{Decoder: d}
	var err error
	if d.AppFilter != "" {
		if cd.app, err = regexp.Compile(d.AppFilter); err != nil {
			return cd, fmt.Errorf("app_filter: %w", err)
		}
	}
	switch d.Type {
	case models.DecoderIPTables:
		if d.Pattern != "" {
			if cd.re, err = regexp.Compile(d.Pattern); err != nil {
				return cd, fmt.Errorf("pattern: %w", err)
			}
		}
	case models.DecoderRegex:
		if d.Pattern == "" {
			return cd, fmt.Errorf("pattern: required for regex decoder")
		}
		if cd.re, err = regexp.Compile(d.Pattern); err != nil {
			return cd, fmt.Errorf("pattern: %w", err)
		}
	default:
		return cd, fmt.Errorf("unknown decoder type %q", d.Type)
	}
	return cd, nil
}

func CompileRule(r models.SeverityRule) (compiledRule, error) {
	cr := compiledRule{SeverityRule: r}
	if len(r.Conditions) == 0 {
		return cr, fmt.Errorf("at least one condition is required")
	}
	for i, c := range r.Conditions {
		if strings.TrimSpace(c.Field) == "" {
			return cr, fmt.Errorf("condition %d: field is required", i+1)
		}
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			return cr, fmt.Errorf("condition %d: %w", i+1, err)
		}
		cr.conds = append(cr.conds, compiledCond{field: c.Field, re: re, negate: c.Negate})
	}
	return cr, nil
}

// Analyze parses and evaluates a message without storing it.
func (e *Engine) Analyze(raw, remote string) Result {
	ev := newEvent(raw, remote)

	e.mu.RLock()
	defer e.mu.RUnlock()

	e.decode(&ev)
	crit, matched, top := e.score(&ev)
	ev.Criticality = crit
	ev.MatchedRules = strings.Join(matched, ", ")
	flowOnly := e.learning && ev.Fields["class"] != ""
	return Result{
		Event:     ev,
		Matched:   matched,
		TopRule:   top,
		Alarm:     crit >= e.threshold && !flowOnly,
		Threshold: e.threshold,
		FlowOnly:  flowOnly,
	}
}

// TryDecoder runs a single (possibly unsaved) decoder against a message.
func (e *Engine) TryDecoder(d models.Decoder, raw string) (models.Event, bool, error) {
	cd, err := CompileDecoder(d)
	if err != nil {
		return models.Event{}, false, err
	}
	ev := newEvent(raw, "")
	e.mu.RLock()
	defer e.mu.RUnlock()
	return ev, e.applyDecoder(cd, &ev), nil
}

func newEvent(raw, remote string) models.Event {
	now := time.Now().UTC()
	msg := syslog.Parse(raw, now)
	ev := models.Event{
		ReceivedAt: now,
		SourceIP:   remote,
		Facility:   msg.Facility,
		Severity:   msg.Severity,
		Timestamp:  msg.Timestamp.UTC(),
		Hostname:   msg.Hostname,
		AppName:    msg.AppName,
		ProcID:     msg.ProcID,
		Message:    msg.Message,
		Raw:        strings.TrimRight(raw, "\r\n\x00"),
		Format:     msg.Format,
		Fields:     models.JSONMap{},
		Tags:       models.StringList{},
	}
	if ev.Hostname == "" {
		ev.Hostname = remote
	}
	return ev
}

// decode applies the first matching decoder (ordered by priority).
func (e *Engine) decode(ev *models.Event) {
	for _, d := range e.decoders {
		if e.applyDecoder(d, ev) {
			return
		}
	}
}

func (e *Engine) applyDecoder(d compiledDecoder, ev *models.Event) bool {
	if d.app != nil && !d.app.MatchString(ev.AppName) {
		return false
	}
	switch d.Type {
	case models.DecoderIPTables:
		if d.re != nil && !d.re.MatchString(ev.Message) {
			return false
		}
		fields, ok := ParseIPTables(ev.Message)
		if !ok {
			return false
		}
		class, reason := e.classify(fields)
		fields["class"] = class
		fields["class_reason"] = reason
		for k, v := range fields {
			ev.Fields[k] = v
		}
		ev.Tags.Add(d.Tags...)
		ev.Tags.Add(class)
		if a := fields["action"]; a != "" {
			ev.Tags.Add(a)
		}
	case models.DecoderRegex:
		m := d.re.FindStringSubmatch(ev.Message)
		if m == nil {
			return false
		}
		for i, name := range d.re.SubexpNames() {
			if name != "" && m[i] != "" {
				ev.Fields[name] = m[i]
			}
		}
		ev.Tags.Add(d.Tags...)
	default:
		return false
	}
	ev.Decoder = d.Name
	return true
}

// classify tags iptables traffic. Precedence:
//  1. a WHITE/BLACK/GREY word in the log prefix (set by --log-prefix),
//  2. BLACK if source or destination is on the black list,
//  3. WHITE if the source is on the white list,
//  4. otherwise GREY.
func (e *Engine) classify(f map[string]string) (string, string) {
	if c := prefixClass(f["prefix"]); c != "" {
		return c, "prefix"
	}
	src, dst := net.ParseIP(f["src_ip"]), net.ParseIP(f["dst_ip"])
	if n := e.lookup(models.ClassBlack, src, dst); n != nil {
		return models.ClassBlack, "list:" + n.net.String()
	}
	if n := e.lookup(models.ClassWhite, src); n != nil {
		return models.ClassWhite, "list:" + n.net.String()
	}
	return models.ClassGrey, "default"
}

func (e *Engine) lookup(list string, ips ...net.IP) *listNet {
	for i := range e.nets {
		n := &e.nets[i]
		if n.list != list {
			continue
		}
		for _, ip := range ips {
			if ip != nil && n.net.Contains(ip) {
				return n
			}
		}
	}
	return nil
}

// score evaluates the rules in priority order. The resulting criticality is
// the highest of all matching rules; a matching rule with Stop ends the
// evaluation.
func (e *Engine) score(ev *models.Event) (int, []string, string) {
	crit, top := 0, ""
	matched := []string{}
	for _, r := range e.rules {
		if !r.matches(ev) {
			continue
		}
		matched = append(matched, r.Name)
		if top == "" || r.Criticality > crit {
			crit, top = r.Criticality, r.Name
		}
		if r.Stop {
			break
		}
	}
	return crit, matched, top
}

func (r compiledRule) matches(ev *models.Event) bool {
	for _, c := range r.conds {
		hit := false
		for _, v := range FieldValues(ev, c.field) {
			if c.re.MatchString(v) {
				hit = true
				break
			}
		}
		if hit == c.negate {
			return false
		}
	}
	return true
}

// FieldValues resolves a rule field name against an event. Built-in names
// refer to syslog attributes; anything else (optionally prefixed with
// "fields.") refers to a decoded field. "tags" yields one value per tag.
func FieldValues(ev *models.Event, field string) []string {
	switch strings.ToLower(field) {
	case "message", "msg":
		return []string{ev.Message}
	case "raw":
		return []string{ev.Raw}
	case "hostname", "host":
		return []string{ev.Hostname}
	case "app_name", "app", "program":
		return []string{ev.AppName}
	case "source_ip", "sender":
		return []string{ev.SourceIP}
	case "decoder":
		return []string{ev.Decoder}
	case "tags", "tag":
		return ev.Tags
	case "syslog_severity", "severity":
		return []string{strconv.Itoa(ev.Severity)}
	case "facility":
		return []string{strconv.Itoa(ev.Facility)}
	}
	key := strings.TrimPrefix(field, "fields.")
	if v, ok := ev.Fields[key]; ok {
		return []string{v}
	}
	return nil
}

// Process analyses, stores and publishes a message, raising an alarm when
// the threshold is reached. Classified iptables traffic is also counted as a
// flow; in learning mode only the flow is kept and the returned event is nil.
func (e *Engine) Process(raw, remote string) (*models.Event, *models.Alarm, error) {
	res := e.Analyze(raw, remote)
	ev := res.Event
	var alarm *models.Alarm
	var flow *models.Flow
	err := e.db.Transaction(func(tx *gorm.DB) error {
		if ev.Fields["class"] != "" {
			flow = flowOf(&ev)
			if err := upsertFlow(tx, flow); err != nil {
				return err
			}
		}
		if res.FlowOnly {
			return nil
		}
		if err := tx.Create(&ev).Error; err != nil {
			return err
		}
		if !res.Alarm {
			return nil
		}
		a := models.Alarm{
			EventID:     ev.ID,
			Criticality: ev.Criticality,
			Title:       alarmTitle(&ev, res.TopRule),
			Summary:     truncate(ev.Message, 300),
			Rules:       ev.MatchedRules,
		}
		if err := tx.Create(&a).Error; err != nil {
			return err
		}
		ev.AlarmID = &a.ID
		alarm = &a
		return tx.Model(&models.Event{}).Where("id = ?", ev.ID).Update("alarm_id", a.ID).Error
	})
	if err != nil {
		return nil, nil, err
	}
	if flow != nil {
		e.Hub.Publish("flow", flow)
	}
	if res.FlowOnly {
		return nil, nil, nil
	}
	e.Hub.Publish("event", ev)
	if alarm != nil {
		alarm.Event = &ev
		e.Hub.Publish("alarm", alarm)
	}
	return &ev, alarm, nil
}

func flowOf(ev *models.Event) *models.Flow {
	f := ev.Fields
	return &models.Flow{
		Hour:      ev.ReceivedAt.Truncate(time.Hour).Unix(),
		Hostname:  ev.Hostname,
		Class:     f["class"],
		SrcIP:     f["src_ip"],
		DstIP:     f["dst_ip"],
		SrcPort:   f["src_port"],
		DstPort:   f["dst_port"],
		Proto:     f["proto"],
		Action:    f["action"],
		Count:     1,
		MaxCrit:   ev.Criticality,
		FirstSeen: ev.ReceivedAt,
		LastSeen:  ev.ReceivedAt,
	}
}

var flowKey = []clause.Column{
	{Name: "hour"}, {Name: "hostname"}, {Name: "class"}, {Name: "src_ip"}, {Name: "dst_ip"},
	{Name: "src_port"}, {Name: "dst_port"}, {Name: "proto"}, {Name: "action"},
}

func upsertFlow(tx *gorm.DB, f *models.Flow) error {
	return tx.Clauses(clause.OnConflict{
		Columns: flowKey,
		DoUpdates: clause.Assignments(map[string]any{
			"count":     gorm.Expr("flows.count + 1"),
			"max_crit":  gorm.Expr("max(flows.max_crit, excluded.max_crit)"),
			"last_seen": gorm.Expr("excluded.last_seen"),
		}),
	}).Create(f).Error
}

func alarmTitle(ev *models.Event, rule string) string {
	who := ev.Hostname
	if src := ev.Fields["src_ip"]; src != "" {
		who = src + " → " + ev.Hostname
		if dpt := ev.Fields["dst_port"]; dpt != "" {
			who += ":" + dpt
		}
	}
	return fmt.Sprintf("%s (%s)", rule, who)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Enqueue hands a message to the background worker; it never blocks.
func (e *Engine) Enqueue(raw, remote string) {
	select {
	case e.queue <- inbound{raw, remote}:
	default:
		if n := e.dropped.Add(1); n%1000 == 1 {
			log.Printf("ingest queue full, %d messages dropped", n)
		}
	}
}

func (e *Engine) Dropped() uint64 { return e.dropped.Load() }

// Run processes queued messages and applies retention until ctx is done.
func (e *Engine) Run(ctx context.Context) {
	go e.retentionLoop(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case in := <-e.queue:
			if _, _, err := e.Process(in.raw, in.remote); err != nil {
				log.Printf("process: %v", err)
			}
		}
	}
}

func (e *Engine) retentionLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		e.applyRetention()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// applyRetention removes old events and acknowledged alarms. Events that
// belong to an open alarm are kept.
func (e *Engine) applyRetention() {
	e.mu.RLock()
	days := e.retention
	e.mu.RUnlock()
	if days <= 0 {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	e.db.Where("acknowledged = ? AND created_at < ?", true, cutoff).Delete(&models.Alarm{})
	e.db.Where("hour < ?", cutoff.Truncate(time.Hour).Unix()).Delete(&models.Flow{})
	res := e.db.Where("received_at < ? AND id NOT IN (?)", cutoff,
		e.db.Model(&models.Alarm{}).Select("event_id")).Delete(&models.Event{})
	if res.RowsAffected > 0 {
		log.Printf("retention: removed %d events older than %d days", res.RowsAffected, days)
	}
}
