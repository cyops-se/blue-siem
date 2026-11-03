package api

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"blue-siem/internal/engine"
	"blue-siem/internal/forward"
	"blue-siem/internal/store"
)

type forwardDTO struct {
	Enabled         bool           `json:"enabled"`
	Address         string         `json:"address"`
	Protocol        string         `json:"protocol"`
	MinCrit         int            `json:"min_crit"`
	Severity        int            `json:"severity"`
	Mode            string         `json:"mode"`
	Instance        string         `json:"instance"`
	InstanceDefault string         `json:"instance_default"`
	Status          forward.Status `json:"status"`
}

// forwardInput is a partial update; omitted fields keep their value.
type forwardInput struct {
	Enabled  *bool   `json:"enabled"`
	Address  *string `json:"address"`
	Protocol *string `json:"protocol"`
	MinCrit  *int    `json:"min_crit"`
	Severity *int    `json:"severity"`
	Mode     *string `json:"mode"`
	Instance *string `json:"instance"`
}

func (s *Server) currentForward() forwardDTO {
	return forwardDTO{
		Enabled:         store.GetBoolSetting(s.db, store.KeyForwardEnabled),
		Address:         store.GetSetting(s.db, store.KeyForwardAddress),
		Protocol:        store.GetSetting(s.db, store.KeyForwardProtocol),
		MinCrit:         store.GetIntSetting(s.db, store.KeyForwardMinCrit),
		Severity:        store.GetIntSetting(s.db, store.KeyForwardSeverity),
		Mode:            store.GetSetting(s.db, store.KeyForwardMode),
		Instance:        store.GetSetting(s.db, store.KeyForwardInstance),
		InstanceDefault: engine.ForwardInstance(s.db),
		Status:          s.eng.Forwarder.Status(),
	}
}

// merge applies in to the current settings and validates the result. It
// returns the settings to store.
func (s *Server) mergeForward(in *forwardInput) (forwardDTO, map[string]string, error) {
	f := s.currentForward()
	if in.Enabled != nil {
		f.Enabled = *in.Enabled
	}
	if in.Address != nil {
		f.Address = strings.TrimSpace(*in.Address)
	}
	if in.Protocol != nil {
		f.Protocol = strings.ToLower(strings.TrimSpace(*in.Protocol))
	}
	if in.MinCrit != nil {
		f.MinCrit = *in.MinCrit
	}
	if in.Severity != nil {
		f.Severity = *in.Severity
	}
	if in.Mode != nil {
		f.Mode = strings.TrimSpace(*in.Mode)
	}
	if in.Instance != nil {
		f.Instance = strings.TrimSpace(*in.Instance)
	}

	if f.Protocol != forward.ProtoUDP && f.Protocol != forward.ProtoTCP {
		return f, nil, fmt.Errorf("forward protocol must be udp or tcp")
	}
	if f.Address != "" {
		if err := s.validateForwardAddress(f.Address, f.Protocol); err != nil {
			return f, nil, err
		}
	}
	if f.Enabled && f.Address == "" {
		return f, nil, fmt.Errorf("forward address is required when forwarding is enabled")
	}
	if f.MinCrit < 1 || f.MinCrit > 10 {
		return f, nil, fmt.Errorf("forward criticality threshold must be 1–10")
	}
	if f.Severity < 0 || f.Severity > 7 {
		return f, nil, fmt.Errorf("forward severity must be 0–7")
	}
	if f.Mode != forward.ModeOriginal && f.Mode != forward.ModeAlarm {
		return f, nil, fmt.Errorf("forward mode must be original or alarm")
	}
	if f.Instance != "" && !forward.ValidInstance(f.Instance) {
		return f, nil, fmt.Errorf("instance name may only contain letters, digits, '.', '_' and '-' (max 64)")
	}
	return f, map[string]string{
		store.KeyForwardEnabled:  strconv.FormatBool(f.Enabled),
		store.KeyForwardAddress:  f.Address,
		store.KeyForwardProtocol: f.Protocol,
		store.KeyForwardMinCrit:  strconv.Itoa(f.MinCrit),
		store.KeyForwardSeverity: strconv.Itoa(f.Severity),
		store.KeyForwardMode:     f.Mode,
		store.KeyForwardInstance: f.Instance,
	}, nil
}

// validateForwardAddress checks host:port and refuses this instance's own
// syslog listener, which would loop forwarded messages back forever.
func (s *Server) validateForwardAddress(addr, protocol string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host == "" || strings.ContainsAny(host, " \t") {
		return fmt.Errorf("forward address must be host:port, e.g. siem2.example.com:514")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("forward port must be 1–65535")
	}
	own := s.info.SyslogUDP
	if protocol == forward.ProtoTCP {
		own = s.info.SyslogTCP
	}
	if own == "" || !isLocalHost(host) {
		return nil
	}
	if _, ownPort, err := net.SplitHostPort(own); err == nil && ownPort == portStr {
		return fmt.Errorf("forwarding to this instance's own syslog listener (%s) would create a loop", own)
	}
	return nil
}

func isLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// testForward sends one test message to the (possibly unsaved) target. An
// empty body tests the saved settings.
func (s *Server) testForward(w http.ResponseWriter, r *http.Request) {
	var in forwardInput
	if err := readJSON(r, &in); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f, _, err := s.mergeForward(&in)
	if err == nil && f.Address == "" {
		err = fmt.Errorf("forward address is required")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	instance := f.Instance
	if instance == "" {
		instance = f.InstanceDefault
	}
	msg := forward.AlarmMessage(forward.Alarm{Instance: instance, Rule: "Test message", Criticality: 0}, f.Severity, time.Now())
	if err := forward.Test(forward.Config{Enabled: true, Address: f.Address, Protocol: f.Protocol}, msg); err != nil {
		writeError(w, http.StatusBadGateway, "test message could not be sent: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sent": msg})
}
