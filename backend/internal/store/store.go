package store

import (
	"errors"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"blue-siem/internal/models"
)

const (
	KeyAlarmThreshold = "alarm_threshold"
	KeyRetentionDays  = "retention_days"
	KeyLearningMode   = "learning_mode"
)

var defaultSettings = map[string]string{
	KeyAlarmThreshold: "7",
	KeyRetentionDays:  "30",
	KeyLearningMode:   "false",
}

// Open opens (and migrates/seeds) the SQLite database at path.
func Open(path string) (*gorm.DB, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		// SQLite compares times as strings, so every timestamp must be UTC.
		NowFunc: func() time.Time { return time.Now().UTC() },
		Logger: logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
			SlowThreshold:             500 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
		}),
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	// SQLite allows a single writer; serialising avoids SQLITE_BUSY.
	sqlDB.SetMaxOpenConns(1)

	hadFlows := db.Migrator().HasTable(&models.Flow{})
	// The flow key gained hostname, so the old unique index no longer
	// matches the upsert's conflict target.
	oldFlowKey := hadFlows && db.Migrator().HasIndex(&models.Flow{}, "idx_flow_key")
	if oldFlowKey {
		if err := db.Migrator().DropIndex(&models.Flow{}, "idx_flow_key"); err != nil {
			return nil, err
		}
	}
	if err := db.AutoMigrate(&models.Event{}, &models.Decoder{}, &models.SeverityRule{},
		&models.IPListEntry{}, &models.Alarm{}, &models.Setting{}, &models.Flow{}); err != nil {
		return nil, err
	}
	if !hadFlows {
		if err := backfillFlows(db); err != nil {
			return nil, err
		}
	}
	// The added column is NULL for existing rows; NULLs never conflict in a
	// unique index and are not counted as a value, so use an empty hostname.
	if oldFlowKey {
		if err := db.Model(&models.Flow{}).Where("hostname IS NULL").Update("hostname", "").Error; err != nil {
			return nil, err
		}
	}
	if err := seed(db); err != nil {
		return nil, err
	}
	return db, nil
}

// backfillFlows builds the flow table from stored events the first time it
// is created (databases from before the table existed).
func backfillFlows(db *gorm.DB) error {
	f := func(name string) string { return "COALESCE(json_extract(fields, '$." + name + "'), '')" }
	return db.Exec(`INSERT INTO flows (hour, hostname, class, src_ip, dst_ip, src_port, dst_port, proto, action, count, max_crit, first_seen, last_seen)
		SELECT CAST(strftime('%s', substr(received_at, 1, 13) || ':00:00') AS INTEGER), hostname, json_extract(fields, '$.class'),
			` + f("src_ip") + `, ` + f("dst_ip") + `, ` + f("src_port") + `, ` + f("dst_port") + `, ` + f("proto") + `, ` + f("action") + `,
			count(*), max(criticality), min(received_at), max(received_at)
		FROM events WHERE json_extract(fields, '$.class') IS NOT NULL
		GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9`).Error
}

func GetSetting(db *gorm.DB, key string) string {
	var s models.Setting
	if err := db.First(&s, "key = ?", key).Error; err != nil {
		return defaultSettings[key]
	}
	return s.Value
}

func GetIntSetting(db *gorm.DB, key string) int {
	n, err := strconv.Atoi(GetSetting(db, key))
	if err != nil {
		n, _ = strconv.Atoi(defaultSettings[key])
	}
	return n
}

func GetBoolSetting(db *gorm.DB, key string) bool {
	b, err := strconv.ParseBool(GetSetting(db, key))
	if err != nil {
		b, _ = strconv.ParseBool(defaultSettings[key])
	}
	return b
}

func SetSetting(db *gorm.DB, key, value string) error {
	return db.Save(&models.Setting{Key: key, Value: value}).Error
}

func seed(db *gorm.DB) error {
	for k, v := range defaultSettings {
		var s models.Setting
		err := db.First(&s, "key = ?", k).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := SetSetting(db, k, v); err != nil {
				return err
			}
		}
	}

	var n int64
	db.Model(&models.Decoder{}).Count(&n)
	if n == 0 {
		if err := db.Create(DefaultDecoders()).Error; err != nil {
			return err
		}
	}
	db.Model(&models.SeverityRule{}).Count(&n)
	if n == 0 {
		if err := db.Create(DefaultRules()).Error; err != nil {
			return err
		}
	}
	return nil
}

const ipPattern = `[0-9a-fA-F:.]+`

func DefaultDecoders() []models.Decoder {
	return []models.Decoder{
		{
			Name:        "iptables",
			Description: "Netfilter/iptables logs (IN= OUT= SRC= DST= ...). Classified as WHITE/BLACK/GREY by log prefix or IP lists.",
			Type:        models.DecoderIPTables,
			Enabled:     true,
			Priority:    10,
			Tags:        models.StringList{"iptables", "firewall"},
		},
		{
			Name:        "sshd-failed",
			Description: "Failed SSH login",
			Type:        models.DecoderRegex,
			Enabled:     true,
			Priority:    20,
			AppFilter:   `^sshd$`,
			Pattern:     `Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>` + ipPattern + `) port (?P<src_port>\d+)`,
			Tags:        models.StringList{"auth", "ssh", "auth_failure"},
		},
		{
			Name:        "sshd-invalid-user",
			Description: "SSH attempt with unknown user",
			Type:        models.DecoderRegex,
			Enabled:     true,
			Priority:    21,
			AppFilter:   `^sshd$`,
			Pattern:     `Invalid user (?P<user>\S*) from (?P<src_ip>` + ipPattern + `)(?: port (?P<src_port>\d+))?`,
			Tags:        models.StringList{"auth", "ssh", "invalid_user"},
		},
		{
			Name:        "sshd-accepted",
			Description: "Successful SSH login",
			Type:        models.DecoderRegex,
			Enabled:     true,
			Priority:    22,
			AppFilter:   `^sshd$`,
			Pattern:     `Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src_ip>` + ipPattern + `) port (?P<src_port>\d+)`,
			Tags:        models.StringList{"auth", "ssh", "auth_success"},
		},
		{
			Name:        "sudo",
			Description: "sudo commands",
			Type:        models.DecoderRegex,
			Enabled:     true,
			Priority:    30,
			AppFilter:   `^sudo$`,
			Pattern:     `^\s*(?P<user>\S+) : (?:(?P<reason>[^;]*?)\s*;\s*)?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.*)$`,
			Tags:        models.StringList{"privilege", "sudo"},
		},
		{
			Name:        "pam-auth-failure",
			Description: "PAM authentication failure (su, login etc.)",
			Type:        models.DecoderRegex,
			Enabled:     true,
			Priority:    40,
			Pattern:     `pam_unix\((?P<service>[^:)]+):auth\): authentication failure;.*?\bruser=(?P<ruser>\S*)\s+rhost=(?P<src_ip>\S*)(?:\s+user=(?P<user>\S+))?`,
			Tags:        models.StringList{"auth", "auth_failure", "pam"},
		},
	}
}

func cond(field, pattern string) models.Condition {
	return models.Condition{Field: field, Pattern: pattern}
}

func DefaultRules() []models.SeverityRule {
	r := func(prio int, name string, crit int, stop bool, c ...models.Condition) models.SeverityRule {
		return models.SeverityRule{Name: name, Enabled: true, Priority: prio, Criticality: crit, Stop: stop, Conditions: c}
	}
	return []models.SeverityRule{
		r(10, "Whitelisted traffic (WHITE)", 1, true, cond("tags", `^WHITE$`)),
		r(20, "Blacklisted traffic (BLACK)", 9, false, cond("tags", `^BLACK$`)),
		// GREY traffic is allowed through the firewall but logged and must be
		// reviewed, so it lands on the default alarm threshold.
		r(30, "Grey zone (GREY) – allowed, review", 7, false, cond("tags", `^GREY$`)),
		r(35, "GREY to sensitive port", 8, false, cond("tags", `^GREY$`), cond("dst_port", `^(22|23|445|1433|3306|3389|5432|5900)$`)),
		r(40, "Failed login", 5, false, cond("tags", `^auth_failure$`)),
		r(41, "Unknown user (SSH)", 6, false, cond("tags", `^invalid_user$`)),
		r(42, "Login as root", 7, false, cond("tags", `^auth_success$`), cond("user", `^root$`)),
		r(50, "sudo command", 3, false, cond("decoder", `^sudo$`)),
		r(51, "sudo – incorrect password", 7, false, cond("decoder", `^sudo$`), cond("message", `(?i)incorrect password`)),
		r(90, "Syslog emerg/alert/crit", 8, false, cond("syslog_severity", `^[0-2]$`)),
		r(91, "Syslog error", 4, false, cond("syslog_severity", `^3$`)),
	}
}
