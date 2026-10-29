package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"blue-siem/internal/models"
	"blue-siem/internal/store"
)

var fieldNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	qp := r.URL.Query()
	q := s.db.Model(&models.Event{})
	if v := strings.TrimSpace(qp.Get("q")); v != "" {
		like := "%" + v + "%"
		q = q.Where("message LIKE ? OR hostname LIKE ? OR app_name LIKE ? OR fields LIKE ? OR source_ip LIKE ?",
			like, like, like, like, like)
	}
	if v := qp.Get("tag"); v != "" {
		q = q.Where("instr(tags, ?) > 0", ","+v+",")
	}
	if v := qp.Get("decoder"); v != "" {
		if v == "-" {
			q = q.Where("decoder = ''")
		} else {
			q = q.Where("decoder = ?", v)
		}
	}
	if v := qp.Get("hostname"); v != "" {
		q = q.Where("hostname = ?", v)
	}
	// f.<name>=value matches a decoded field exactly (used to drill down
	// from the flow view).
	for k, vs := range qp {
		name, ok := strings.CutPrefix(k, "f.")
		if !ok || !fieldNameRe.MatchString(name) {
			continue
		}
		q = q.Where("COALESCE(json_extract(fields, ?), '') = ?", "$."+name, vs[0])
	}
	if v := qp.Get("min_crit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q = q.Where("criticality >= ?", n)
		}
	}
	if v := qp.Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			q = q.Where("received_at >= ?", time.Now().UTC().Add(-time.Duration(n)*time.Hour))
		}
	}
	q = q.Session(&gorm.Session{})

	var total int64
	if err := q.Count(&total).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items := []models.Event{}
	limit := intQuery(r, "limit", 100, 1, 1000)
	offset := intQuery(r, "offset", 0, 0, 1<<30)
	if err := q.Order("id desc").Limit(limit).Offset(offset).Find(&items).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var ev models.Event
	if err := s.db.First(&ev, id).Error; err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// clearEvents deletes all events and alarms.
func (s *Server) clearEvents(w http.ResponseWriter, r *http.Request) {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&models.Alarm{}).Error; err != nil {
			return err
		}
		return tx.Where("1 = 1").Delete(&models.Event{}).Error
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.eng.Hub.Publish("cleared", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAlarms(w http.ResponseWriter, r *http.Request) {
	q := s.db.Model(&models.Alarm{})
	switch r.URL.Query().Get("status") {
	case "acked":
		q = q.Where("acknowledged = ?", true)
	case "all":
	default:
		q = q.Where("acknowledged = ?", false)
	}
	q = q.Session(&gorm.Session{})
	var total int64
	q.Count(&total)
	items := []models.Alarm{}
	limit := intQuery(r, "limit", 200, 1, 1000)
	offset := intQuery(r, "offset", 0, 0, 1<<30)
	if err := q.Preload("Event").Order("id desc").Limit(limit).Offset(offset).Find(&items).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

type ackRequest struct {
	IDs     []uint `json:"ids"`
	All     bool   `json:"all"`
	User    string `json:"user"`
	Comment string `json:"comment"`
}

func (s *Server) ackAlarm(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req ackRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.IDs, req.All = []uint{id}, false
	s.doAck(w, req)
}

func (s *Server) ackAlarms(w http.ResponseWriter, r *http.Request) {
	var req ackRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.IDs) == 0 && !req.All {
		writeError(w, http.StatusBadRequest, "ids or all is required")
		return
	}
	s.doAck(w, req)
}

func (s *Server) doAck(w http.ResponseWriter, req ackRequest) {
	req.User = strings.TrimSpace(req.User)
	if req.User == "" {
		writeError(w, http.StatusBadRequest, "user is required (who acknowledges)")
		return
	}
	now := time.Now().UTC()
	q := s.db.Model(&models.Alarm{}).Where("acknowledged = ?", false)
	if !req.All {
		q = q.Where("id IN ?", req.IDs)
	}
	res := q.Updates(map[string]any{
		"acknowledged": true,
		"acked_at":     now,
		"acked_by":     req.User,
		"ack_comment":  req.Comment,
	})
	if res.Error != nil {
		writeError(w, http.StatusInternalServerError, res.Error.Error())
		return
	}
	s.eng.Hub.Publish("ack", map[string]any{"ids": req.IDs, "all": req.All, "count": res.RowsAffected})
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": res.RowsAffected})
}

type countRow struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
	Max   int    `json:"max,omitempty"`
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	hours := intQuery(r, "hours", 24, 1, 24*90)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	recent := func() *gorm.DB { return s.db.Model(&models.Event{}).Where("received_at >= ?", since) }

	out := map[string]any{"hours": hours}
	var n int64
	s.db.Model(&models.Event{}).Count(&n)
	out["events_total"] = n
	recent().Count(&n)
	out["events_recent"] = n
	s.db.Model(&models.Alarm{}).Where("acknowledged = ?", false).Count(&n)
	out["alarms_open"] = n
	s.db.Model(&models.Alarm{}).Where("created_at >= ?", since).Count(&n)
	out["alarms_recent"] = n

	classes := map[string]int64{}
	for _, c := range []string{models.ClassWhite, models.ClassGrey, models.ClassBlack} {
		recent().Where("instr(tags, ?) > 0", ","+c+",").Count(&n)
		classes[c] = n
	}
	out["classes"] = classes

	var byCrit []countRow
	recent().Select("CAST(criticality AS TEXT) AS key, count(*) AS count").Group("criticality").Order("criticality").Scan(&byCrit)
	out["by_criticality"] = nonNil(byCrit)

	var byDecoder []countRow
	recent().Select("CASE decoder WHEN '' THEN '-' ELSE decoder END AS key, count(*) AS count").
		Group("decoder").Order("count DESC").Scan(&byDecoder)
	out["by_decoder"] = nonNil(byDecoder)

	var topSrc []countRow
	recent().Select("json_extract(fields, '$.src_ip') AS key, count(*) AS count, max(criticality) AS max").
		Where("json_extract(fields, '$.src_ip') IS NOT NULL").
		Group("key").Order("count DESC").Limit(10).Scan(&topSrc)
	out["top_sources"] = nonNil(topSrc)

	// Times are stored in UTC as "YYYY-MM-DD HH:MM:SS..." so the first 13
	// characters identify the hour.
	var timeline []countRow
	recent().Select("substr(received_at, 1, 13) AS key, count(*) AS count, max(criticality) AS max").
		Group("key").Order("key").Scan(&timeline)
	out["timeline"] = nonNil(timeline)

	out["dropped"] = s.eng.Dropped()
	writeJSON(w, http.StatusOK, out)
}

func nonNil(rows []countRow) []countRow {
	if rows == nil {
		return []countRow{}
	}
	return rows
}

type settingsDTO struct {
	AlarmThreshold int    `json:"alarm_threshold"`
	RetentionDays  int    `json:"retention_days"`
	LearningMode   bool   `json:"learning_mode"`
	SyslogUDP      string `json:"syslog_udp"`
	SyslogTCP      string `json:"syslog_tcp"`
	Version        string `json:"version"`
}

func (s *Server) currentSettings() settingsDTO {
	return settingsDTO{
		AlarmThreshold: store.GetIntSetting(s.db, store.KeyAlarmThreshold),
		RetentionDays:  store.GetIntSetting(s.db, store.KeyRetentionDays),
		LearningMode:   store.GetBoolSetting(s.db, store.KeyLearningMode),
		SyslogUDP:      s.info.SyslogUDP,
		SyslogTCP:      s.info.SyslogTCP,
		Version:        s.info.Version,
	}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.currentSettings())
}

// putSettings updates the settings present in the body; omitted ones are
// left unchanged.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AlarmThreshold *int  `json:"alarm_threshold"`
		RetentionDays  *int  `json:"retention_days"`
		LearningMode   *bool `json:"learning_mode"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var errs []error
	if v := in.AlarmThreshold; v != nil {
		if *v < 1 || *v > 10 {
			writeError(w, http.StatusBadRequest, "alarm threshold must be 1–10")
			return
		}
		errs = append(errs, store.SetSetting(s.db, store.KeyAlarmThreshold, strconv.Itoa(*v)))
	}
	if v := in.RetentionDays; v != nil {
		if *v < 0 {
			writeError(w, http.StatusBadRequest, "retention days cannot be negative")
			return
		}
		errs = append(errs, store.SetSetting(s.db, store.KeyRetentionDays, strconv.Itoa(*v)))
	}
	if v := in.LearningMode; v != nil {
		errs = append(errs, store.SetSetting(s.db, store.KeyLearningMode, strconv.FormatBool(*v)))
	}
	if err := errors.Join(errs...); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.reload(w) {
		cur := s.currentSettings()
		s.eng.Hub.Publish("settings", cur)
		writeJSON(w, http.StatusOK, cur)
	}
}

type messageRequest struct {
	Raw      string `json:"raw"`
	SourceIP string `json:"source_ip"`
}

func (m *messageRequest) lines() []string {
	var out []string
	for _, l := range strings.Split(m.Raw, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimRight(l, "\r"))
		}
	}
	return out
}

func (m *messageRequest) source(r *http.Request) string {
	if m.SourceIP != "" {
		return m.SourceIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// test analyses messages without storing them.
func (s *Server) test(w http.ResponseWriter, r *http.Request) {
	var req messageRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	lines := req.lines()
	if len(lines) == 0 {
		writeError(w, http.StatusBadRequest, "no message")
		return
	}
	if len(lines) > 100 {
		lines = lines[:100]
	}
	src := req.source(r)
	results := make([]any, 0, len(lines))
	for _, l := range lines {
		results = append(results, s.eng.Analyze(l, src))
	}
	writeJSON(w, http.StatusOK, results)
}

// testDecoder runs an unsaved decoder against sample messages.
func (s *Server) testDecoder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Decoder models.Decoder `json:"decoder"`
		Raw     string         `json:"raw"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Decoder.Name == "" {
		req.Decoder.Name = "test"
	}
	if err := validateDecoder(&req.Decoder); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	type result struct {
		Matched bool         `json:"matched"`
		Event   models.Event `json:"event"`
	}
	results := []result{}
	for _, l := range (&messageRequest{Raw: req.Raw}).lines() {
		ev, ok, err := s.eng.TryDecoder(req.Decoder, l)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		results = append(results, result{ok, ev})
	}
	writeJSON(w, http.StatusOK, results)
}

// ingest stores messages as if they had been received over syslog.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	var req messageRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	src := req.source(r)
	events, alarms, flowOnly := 0, 0, 0
	for _, l := range req.lines() {
		ev, a, err := s.eng.Process(l, src)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ev == nil {
			flowOnly++
			continue
		}
		events++
		if a != nil {
			alarms++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"events": events, "alarms": alarms, "flow_only": flowOnly})
}

// stream is a Server-Sent Events feed of hub notifications.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.eng.Hub.Subscribe()
	defer s.eng.Hub.Unsubscribe(ch)

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
		}
		flusher.Flush()
	}
}
