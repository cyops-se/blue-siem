package api

import (
	"fmt"
	"net"
	"strings"

	"blue-siem/internal/engine"
	"blue-siem/internal/models"
)

// Validators normalise input and reset the ID (the URL decides which row is
// updated; new rows get a fresh one).

func cleanTags(in models.StringList) models.StringList {
	out := models.StringList{}
	out.Add(in...)
	return out
}

func validateDecoder(d *models.Decoder) error {
	d.ID = 0
	d.Name = strings.TrimSpace(d.Name)
	if d.Name == "" {
		return fmt.Errorf("name is required")
	}
	if d.Type == "" {
		d.Type = models.DecoderRegex
	}
	d.Tags = cleanTags(d.Tags)
	_, err := engine.CompileDecoder(*d)
	return err
}

func validateRule(r *models.SeverityRule) error {
	r.ID = 0
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.Criticality < 0 || r.Criticality > 10 {
		return fmt.Errorf("criticality must be 0–10")
	}
	for i := range r.Conditions {
		r.Conditions[i].Field = strings.TrimSpace(r.Conditions[i].Field)
	}
	_, err := engine.CompileRule(*r)
	return err
}

func validateIPEntry(e *models.IPListEntry) error {
	e.ID = 0
	e.List = strings.ToUpper(strings.TrimSpace(e.List))
	if e.List != models.ClassWhite && e.List != models.ClassBlack {
		return fmt.Errorf("list must be WHITE or BLACK")
	}
	cidr := strings.TrimSpace(e.CIDR)
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %q", cidr)
		}
		if ip.To4() != nil {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid network: %q", cidr)
	}
	e.CIDR = n.String()
	return nil
}
