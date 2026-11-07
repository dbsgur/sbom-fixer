package fixer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// orderedObject is a JSON object that remembers key order, so editing
// package.json does not reshuffle the user's file.
type orderedObject struct {
	keys   []string
	values map[string]json.RawMessage
}

func parseOrdered(data []byte) (*orderedObject, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("JSON 객체가 아닙니다")
	}
	o := &orderedObject{values: map[string]json.RawMessage{}}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if _, dup := o.values[key]; !dup {
			o.keys = append(o.keys, key)
		}
		o.values[key] = raw
	}
	return o, nil
}

func (o *orderedObject) has(key string) bool {
	_, ok := o.values[key]
	return ok
}

// child returns the nested object under key (created if missing).
func (o *orderedObject) child(key string) (*orderedObject, error) {
	raw, ok := o.values[key]
	if !ok || len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return &orderedObject{values: map[string]json.RawMessage{}}, nil
	}
	return parseOrdered(raw)
}

func (o *orderedObject) setRaw(key string, raw json.RawMessage) {
	if !o.has(key) {
		o.keys = append(o.keys, key)
	}
	o.values[key] = raw
}

func (o *orderedObject) setString(key, val string) {
	b, _ := json.Marshal(val)
	o.setRaw(key, b)
}

func (o *orderedObject) getString(key string) (string, bool) {
	raw, ok := o.values[key]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func (o *orderedObject) setChild(key string, c *orderedObject) error {
	b, err := c.marshalCompact()
	if err != nil {
		return err
	}
	o.setRaw(key, b)
	return nil
}

func (o *orderedObject) marshalCompact() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		var c bytes.Buffer
		if err := json.Compact(&c, o.values[k]); err != nil {
			return nil, err
		}
		buf.Write(c.Bytes())
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshalIndent renders the object with the given indent, keeping key order
// and escaping like npm does (no HTML escaping).
func (o *orderedObject) marshalIndent(indent string) ([]byte, error) {
	compact, err := o.marshalCompact()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", indent); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// detectIndent guesses the indent unit used in a JSON file (default 2 spaces).
func detectIndent(data []byte) string {
	for _, line := range strings.Split(string(data), "\n")[1:] {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || len(trimmed) == len(line) {
			continue
		}
		return line[:len(line)-len(trimmed)]
	}
	return "  "
}
