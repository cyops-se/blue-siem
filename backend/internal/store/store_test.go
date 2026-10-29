package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"blue-siem/internal/models"
)

func TestBackfillFlows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 29, 10, 15, 0, 0, time.UTC)
	fields := models.JSONMap{"class": "BLACK", "src_ip": "8.8.8.8", "dst_ip": "10.0.0.1", "dst_port": "22", "proto": "TCP", "action": "DROP"}
	db.Create(&[]models.Event{
		{ReceivedAt: at, Fields: fields, Criticality: 9},
		{ReceivedAt: at.Add(10 * time.Minute), Fields: fields, Criticality: 9},
		{ReceivedAt: at.Add(time.Hour), Fields: fields, Criticality: 9},
		{ReceivedAt: at, Fields: models.JSONMap{"user": "root"}},
	})
	// Simulate a database from before the flow table existed.
	db.Migrator().DropTable(&models.Flow{})
	sqlDB, _ := db.DB()
	sqlDB.Close()

	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()
	var flows []models.Flow
	db.Order("hour").Find(&flows)
	if len(flows) != 2 {
		t.Fatalf("flows %+v", flows)
	}
	f := flows[0]
	if f.Hour != at.Truncate(time.Hour).Unix() || f.Count != 2 || f.Class != "BLACK" || f.SrcPort != "" ||
		f.Action != "DROP" || f.MaxCrit != 9 || !f.FirstSeen.Equal(at) || !f.LastSeen.Equal(at.Add(10*time.Minute)) {
		t.Errorf("flow %+v", f)
	}
}

func TestMigrateFlowKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the flow table as it was before hostname was added.
	m := db.Migrator()
	if err := errors.Join(
		m.DropIndex(&models.Flow{}, "idx_flows_key"),
		m.DropColumn(&models.Flow{}, "hostname"),
		db.Exec("CREATE UNIQUE INDEX idx_flow_key ON flows (hour, class, src_ip, dst_ip, src_port, dst_port, proto, action)").Error,
		db.Exec("INSERT INTO flows (hour, class, src_ip, count) VALUES (1, 'GREY', '1.2.3.4', 5)").Error,
	); err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.Close()

	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()
	m = db.Migrator()
	if m.HasIndex(&models.Flow{}, "idx_flow_key") || !m.HasIndex(&models.Flow{}, "idx_flows_key") || !m.HasColumn(&models.Flow{}, "hostname") {
		t.Error("flow key not migrated")
	}
	var f models.Flow
	if db.First(&f).Error != nil || f.Count != 5 || f.Hostname != "" {
		t.Errorf("existing flow %+v", f)
	}
	var nulls int64
	db.Model(&models.Flow{}).Where("hostname IS NULL").Count(&nulls)
	if nulls != 0 {
		t.Errorf("%d flows with NULL hostname", nulls)
	}
}
