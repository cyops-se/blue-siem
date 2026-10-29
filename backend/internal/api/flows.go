package api

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"

	"blue-siem/internal/models"
)

// flowFields are the fields a flow can be grouped by, in display order:
// the log source (hostname) followed by the iptables 5-tuple.
var flowFields = []string{"hostname", "src_ip", "dst_ip", "src_port", "dst_port", "proto"}

type flowRow struct {
	Hostname  string `json:"hostname"`
	Class     string `json:"class"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   string `json:"src_port"`
	DstPort   string `json:"dst_port"`
	Proto     string `json:"proto"`
	Actions   string `json:"actions"`
	Count     int64  `json:"count"`
	MaxCrit   int    `json:"max_crit"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`

	// Number of distinct values per field (1 for grouped fields) and, for
	// fields that are not grouped, a truncated list of them.
	NHostname int64  `gorm:"column:n_hostname" json:"n_hostname"`
	NSrcIP    int64  `gorm:"column:n_src_ip" json:"n_src_ip"`
	NDstIP    int64  `gorm:"column:n_dst_ip" json:"n_dst_ip"`
	NSrcPort  int64  `gorm:"column:n_src_port" json:"n_src_port"`
	NDstPort  int64  `gorm:"column:n_dst_port" json:"n_dst_port"`
	NProto    int64  `gorm:"column:n_proto" json:"n_proto"`
	SHostname string `gorm:"column:s_hostname" json:"s_hostname"`
	SSrcIP    string `gorm:"column:s_src_ip" json:"s_src_ip"`
	SDstIP    string `gorm:"column:s_dst_ip" json:"s_dst_ip"`
	SSrcPort  string `gorm:"column:s_src_port" json:"s_src_port"`
	SDstPort  string `gorm:"column:s_dst_port" json:"s_dst_port"`
	SProto    string `gorm:"column:s_proto" json:"s_proto"`
}

// sampleLen limits the list of distinct values returned for a field that is
// not grouped.
const sampleLen = 300

type flowClassRow struct {
	Class  string `json:"class"`
	Flows  int64  `json:"flows"`
	Events int64  `json:"events"`
}

type flowSourceRow struct {
	Hostname string `json:"hostname"`
	Flows    int64  `json:"flows"`
	Events   int64  `json:"events"`
}

// groupFlows sums the flow counters per class and the given fields. Fields
// that are not grouped get their value only when it is the same for the
// whole group, plus the number of distinct values and a sample of them.
func groupFlows(q *gorm.DB, fields []string) *gorm.DB {
	groupBy := strings.Join(append([]string{"class"}, fields...), ", ")
	cols := []string{"class"}
	for _, f := range flowFields {
		if slices.Contains(fields, f) {
			cols = append(cols, f, "1 AS n_"+f, "'' AS s_"+f)
			continue
		}
		cols = append(cols,
			fmt.Sprintf("CASE count(DISTINCT %[1]s) WHEN 1 THEN max(%[1]s) ELSE '' END AS %[1]s", f),
			fmt.Sprintf("count(DISTINCT %[1]s) AS n_%[1]s", f),
			fmt.Sprintf("COALESCE(substr(group_concat(DISTINCT %[1]s), 1, %[2]d), '') AS s_%[1]s", f, sampleLen),
		)
	}
	cols = append(cols,
		"sum(count) AS count",
		"max(max_crit) AS max_crit",
		"min(first_seen) AS first_seen",
		"max(last_seen) AS last_seen",
		"COALESCE(group_concat(DISTINCT NULLIF(action, '')), '') AS actions",
	)
	return q.Select(strings.Join(cols, ", ")).Group(groupBy).Session(&gorm.Session{})
}

// listFlows summarises the hourly flow counters: one row per class and
// combination of the grouped fields. The class and source summaries each
// ignore their own filter so that all choices stay visible.
func (s *Server) listFlows(w http.ResponseWriter, r *http.Request) {
	qp := r.URL.Query()
	group := flowFields
	if v, ok := qp["group"]; ok {
		want := map[string]bool{}
		for _, f := range strings.Split(v[0], ",") {
			want[strings.TrimSpace(f)] = true
		}
		group = nil
		for _, f := range flowFields {
			if want[f] {
				group = append(group, f)
			}
		}
	}

	base := s.db.Model(&models.Flow{})
	if n := intQuery(r, "hours", 0, 0, 24*365); n > 0 {
		base = base.Where("hour >= ?", time.Now().UTC().Add(-time.Duration(n)*time.Hour).Truncate(time.Hour).Unix())
	}
	if v := strings.TrimSpace(qp.Get("q")); v != "" {
		like := "%" + v + "%"
		var ors []string
		var args []any
		for _, f := range flowFields {
			ors = append(ors, f+" LIKE ?")
			args = append(args, like)
		}
		base = base.Where(strings.Join(ors, " OR "), args...)
	}
	base = base.Session(&gorm.Session{})
	allSources := base
	if v, ok := qp["hostname"]; ok {
		base = base.Where("hostname = ?", v[0])
	}
	class := strings.ToUpper(qp.Get("class"))

	sortable := map[string]string{
		"class": "class", "count": "count", "max_crit": "max_crit",
		"first_seen": "first_seen", "last_seen": "last_seen",
	}
	// Fields that are not grouped sort by their number of distinct values.
	for _, f := range flowFields {
		switch {
		case !slices.Contains(group, f):
			sortable[f] = "n_" + f
		case strings.HasSuffix(f, "_port"):
			sortable[f] = "CAST(" + f + " AS INTEGER)"
		default:
			sortable[f] = f
		}
	}
	grouped := groupFlows(base, group)

	classes := []flowClassRow{}
	if err := s.db.Table("(?) AS f", grouped).
		Select("class, count(*) AS flows, sum(count) AS events").
		Group("class").Scan(&classes).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Flows per source are counted with hostname grouped even when the
	// table is not, so the numbers match what selecting the source shows.
	bySource := allSources
	if class != "" {
		bySource = bySource.Where("class = ?", class)
	}
	withHost := group
	if !slices.Contains(group, "hostname") {
		withHost = append([]string{"hostname"}, group...)
	}
	sources := []flowSourceRow{}
	if err := s.db.Table("(?) AS f", groupFlows(bySource, withHost)).
		Select("hostname, count(*) AS flows, sum(count) AS events").
		Group("hostname").Order("events DESC").Scan(&sources).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	items := grouped
	if class != "" {
		items = items.Where("class = ?", class)
	}
	var total int64
	if err := s.db.Table("(?) AS f", items).Count(&total).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	order, ok := sortable[qp.Get("sort")]
	if !ok {
		order = "count"
	}
	if qp.Get("order") == "asc" {
		order += " ASC"
	} else {
		order += " DESC"
	}
	rows := []flowRow{}
	limit := intQuery(r, "limit", 100, 1, 1000)
	offset := intQuery(r, "offset", 0, 0, 1<<30)
	if err := items.Order(order).Order("count DESC").Limit(limit).Offset(offset).Scan(&rows).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range rows {
		rows[i].FirstSeen = isoTime(rows[i].FirstSeen)
		rows[i].LastSeen = isoTime(rows[i].LastSeen)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":   rows,
		"total":   total,
		"group":   append([]string{}, group...),
		"classes": classes,
		"sources": sources,
	})
}

// isoTime converts an aggregated SQLite timestamp (which comes back as text)
// to RFC 3339 so that browsers parse it reliably.
func isoTime(s string) string {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	return s
}

// clearFlows deletes all flow counters, e.g. to restart learning.
func (s *Server) clearFlows(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Where("1 = 1").Delete(&models.Flow{}).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.eng.Hub.Publish("flows_cleared", nil)
	w.WriteHeader(http.StatusNoContent)
}
