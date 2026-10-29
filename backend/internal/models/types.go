package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
)

func asString(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "", nil
	case string:
		return t, nil
	case []byte:
		return string(t), nil
	default:
		return "", fmt.Errorf("unsupported type %T", v)
	}
}

// StringList is stored as ",a,b," so that a single tag can be matched
// exactly with instr(tags, ',a,').
type StringList []string

func (s StringList) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "", nil
	}
	return "," + strings.Join(s, ",") + ",", nil
}

func (s *StringList) Scan(v any) error {
	str, err := asString(v)
	if err != nil {
		return err
	}
	out := StringList{}
	for _, p := range strings.Split(strings.Trim(str, ","), ",") {
		if p != "" {
			out = append(out, p)
		}
	}
	*s = out
	return nil
}

func (s StringList) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(s))
}

// Has reports whether the list contains tag (case-insensitive).
func (s StringList) Has(tag string) bool {
	for _, t := range s {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// Add appends tags that are not already present. Commas are stripped since
// they are used as separator in the database.
func (s *StringList) Add(tags ...string) {
	for _, t := range tags {
		t = strings.TrimSpace(strings.ReplaceAll(t, ",", ""))
		if t != "" && !s.Has(t) {
			*s = append(*s, t)
		}
	}
}

// JSONMap holds decoded fields as a JSON object.
type JSONMap map[string]string

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(map[string]string(m))
	return string(b), err
}

func (m *JSONMap) Scan(v any) error {
	str, err := asString(v)
	if err != nil {
		return err
	}
	out := JSONMap{}
	if str != "" {
		if err := json.Unmarshal([]byte(str), &out); err != nil {
			return err
		}
	}
	*m = out
	return nil
}

func (m JSONMap) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(map[string]string(m))
}

// Condition is one pattern test against an event field.
type Condition struct {
	Field   string `json:"field"`
	Pattern string `json:"pattern"`
	Negate  bool   `json:"negate"`
}

type Conditions []Condition

func (c Conditions) Value() (driver.Value, error) {
	if c == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]Condition(c))
	return string(b), err
}

func (c *Conditions) Scan(v any) error {
	str, err := asString(v)
	if err != nil {
		return err
	}
	out := Conditions{}
	if str != "" {
		if err := json.Unmarshal([]byte(str), &out); err != nil {
			return err
		}
	}
	*c = out
	return nil
}
