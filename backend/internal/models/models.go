package models

import "time"

const (
	DecoderRegex    = "regex"
	DecoderIPTables = "iptables"

	ClassWhite = "WHITE"
	ClassBlack = "BLACK"
	ClassGrey  = "GREY"
)

// Event is a received and decoded syslog message.
type Event struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	ReceivedAt   time.Time  `gorm:"index" json:"received_at"`
	SourceIP     string     `gorm:"index" json:"source_ip"`
	Facility     int        `json:"facility"`
	Severity     int        `json:"severity"`
	Timestamp    time.Time  `json:"timestamp"`
	Hostname     string     `gorm:"index" json:"hostname"`
	AppName      string     `gorm:"index" json:"app_name"`
	ProcID       string     `json:"proc_id"`
	Message      string     `json:"message"`
	Raw          string     `json:"raw"`
	Format       string     `json:"format"`
	Decoder      string     `gorm:"index" json:"decoder"`
	Fields       JSONMap    `gorm:"type:text" json:"fields"`
	Tags         StringList `gorm:"type:text;index" json:"tags"`
	Criticality  int        `gorm:"index" json:"criticality"`
	MatchedRules string     `json:"matched_rules"`
	AlarmID      *uint      `json:"alarm_id"`
}

// Decoder extracts fields from a message. Type "regex" uses Pattern with
// named groups, type "iptables" uses the built-in netfilter log parser.
type Decoder struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"uniqueIndex" json:"name"`
	Description string     `json:"description"`
	Type        string     `json:"type"`
	Enabled     bool       `json:"enabled"`
	Priority    int        `json:"priority"`
	AppFilter   string     `json:"app_filter"`
	Pattern     string     `json:"pattern"`
	Tags        StringList `gorm:"type:text" json:"tags"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// SeverityRule sets criticality when all conditions match.
type SeverityRule struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Enabled     bool       `json:"enabled"`
	Priority    int        `json:"priority"`
	Conditions  Conditions `gorm:"type:text" json:"conditions"`
	Criticality int        `json:"criticality"`
	Stop        bool       `json:"stop"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// IPListEntry places a network on the WHITE or BLACK list used by the
// iptables classifier.
type IPListEntry struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	List      string    `gorm:"index" json:"list"`
	CIDR      string    `gorm:"column:cidr" json:"cidr"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// Alarm is raised when an event's criticality reaches the threshold and
// stays open until acknowledged.
type Alarm struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time  `gorm:"index" json:"created_at"`
	EventID      uint       `gorm:"index" json:"event_id"`
	Event        *Event     `json:"event,omitempty"`
	Criticality  int        `json:"criticality"`
	Title        string     `json:"title"`
	Summary      string     `json:"summary"`
	Rules        string     `json:"rules"`
	Acknowledged bool       `gorm:"index" json:"acknowledged"`
	AckedAt      *time.Time `json:"acked_at"`
	AckedBy      string     `json:"acked_by"`
	AckComment   string     `json:"ack_comment"`
}

// Flow counts classified iptables traffic per hour for one log source
// (hostname), class, 5-tuple and action. It is updated for every classified message, also in learning
// mode when no event is stored.
type Flow struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Hour      int64     `gorm:"uniqueIndex:idx_flows_key,priority:1" json:"hour"`
	Hostname  string    `gorm:"uniqueIndex:idx_flows_key,priority:2" json:"hostname"`
	Class     string    `gorm:"uniqueIndex:idx_flows_key,priority:3" json:"class"`
	SrcIP     string    `gorm:"column:src_ip;uniqueIndex:idx_flows_key,priority:4" json:"src_ip"`
	DstIP     string    `gorm:"column:dst_ip;uniqueIndex:idx_flows_key,priority:5" json:"dst_ip"`
	SrcPort   string    `gorm:"uniqueIndex:idx_flows_key,priority:6" json:"src_port"`
	DstPort   string    `gorm:"uniqueIndex:idx_flows_key,priority:7" json:"dst_port"`
	Proto     string    `gorm:"uniqueIndex:idx_flows_key,priority:8" json:"proto"`
	Action    string    `gorm:"uniqueIndex:idx_flows_key,priority:9" json:"action"`
	Count     int64     `json:"count"`
	MaxCrit   int       `json:"max_crit"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Setting struct {
	Key   string `gorm:"primaryKey" json:"key"`
	Value string `json:"value"`
}
