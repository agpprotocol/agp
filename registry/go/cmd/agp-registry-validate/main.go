package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const safeMax int64 = 9007199254740991

var idRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._/-]{1,94}[a-z0-9])$`)
var objRE = regexp.MustCompile(`^agp\.[a-z0-9][a-z0-9._-]*/([1-9][0-9]*)$`)

type E struct{ code, detail string }

func (e *E) Error() string  { return e.detail }
func bad(c, d string) error { return &E{c, d} }

type Receipt struct {
	Accepted  bool    `json:"accepted"`
	Detail    *string `json:"detail"`
	ErrorCode *string `json:"error_code"`
}

func parse(dec *json.Decoder) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, bad("INVALID_JSON", err.Error())
	}
	switch x := t.(type) {
	case json.Delim:
		if x == '{' {
			m := map[string]any{}
			seen := map[string]bool{}
			for dec.More() {
				k0, err := dec.Token()
				if err != nil {
					return nil, bad("INVALID_JSON", err.Error())
				}
				k, ok := k0.(string)
				if !ok {
					return nil, bad("INVALID_JSON", "invalid object key")
				}
				if seen[k] {
					return nil, bad("INVALID_JSON", "duplicate JSON member")
				}
				seen[k] = true
				v, err := parse(dec)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, bad("INVALID_JSON", err.Error())
			}
			return m, nil
		}
		if x == '[' {
			a := []any{}
			for dec.More() {
				v, err := parse(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, bad("INVALID_JSON", err.Error())
			}
			return a, nil
		}
	case json.Number:
		s := x.String()
		if strings.ContainsAny(s, ".eE") {
			return nil, bad("INVALID_JSON", "decimal unsupported")
		}
		n, err := x.Int64()
		if err != nil {
			return nil, bad("INVALID_JSON", "invalid integer")
		}
		return n, nil
	default:
		return x, nil
	}
	return nil, bad("INVALID_JSON", "invalid JSON")
}
func parseJSON(raw []byte) (any, error) {
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) || !utf8.Valid(raw) {
		return nil, bad("INVALID_JSON", "invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := parse(d)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, bad("INVALID_JSON", "trailing data")
	}
	return v, nil
}
func obj(v any, c, d string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad(c, d)
	}
	return m, nil
}
func arr(v any, c, d string) ([]any, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, bad(c, d)
	}
	return a, nil
}
func text(m map[string]any, k, w string) (string, error) {
	s, ok := m[k].(string)
	if !ok || s == "" {
		return "", bad("INVALID_ENTRY", w+"."+k+" invalid")
	}
	return s, nil
}
func pos(v any, f string) (int64, error) {
	n, ok := v.(int64)
	if !ok || n < 1 || n > safeMax {
		return 0, bad("INVALID_SAFE_INTEGER", f+" invalid")
	}
	return n, nil
}
func exact(m map[string]any, fs ...string) bool {
	if len(m) != len(fs) {
		return false
	}
	for _, f := range fs {
		if _, ok := m[f]; !ok {
			return false
		}
	}
	return true
}
func validate(v any) error {
	r, err := obj(v, "INVALID_REGISTRY", "registry must be object")
	if err != nil {
		return err
	}
	cols := []string{"objects", "canonicalization_algorithms", "digest_algorithms", "signature_algorithms"}
	allowed := map[string]bool{"registry_version": true}
	for _, c := range cols {
		allowed[c] = true
	}
	for k := range r {
		if !allowed[k] {
			return bad("UNKNOWN_TOP_LEVEL_MEMBER", "unknown member")
		}
	}
	if len(r) != 5 {
		return bad("INVALID_REGISTRY", "missing member")
	}
	if r["registry_version"] != "0.8" {
		return bad("INVALID_REGISTRY_VERSION", "wrong version")
	}
	all := map[string]bool{}
	by := map[string]map[string]map[string]any{}
	for _, c := range cols {
		xs, err := arr(r[c], "INVALID_COLLECTION", c+" invalid")
		if err != nil {
			return err
		}
		ids := []string{}
		by[c] = map[string]map[string]any{}
		for i, rv := range xs {
			w := fmt.Sprintf("%s[%d]", c, i)
			e, err := obj(rv, "INVALID_ENTRY", w+" invalid")
			if err != nil {
				return err
			}
			for _, f := range []string{"id", "status", "spec", "description"} {
				if _, ok := e[f]; !ok {
					return bad("INVALID_ENTRY", w+" missing field")
				}
			}
			id, ok := e["id"].(string)
			if !ok || !idRE.MatchString(id) || len(id) > 96 {
				return bad("INVALID_IDENTIFIER", w+" id invalid")
			}
			if all[id] {
				return bad("DUPLICATE_IDENTIFIER", "duplicate id")
			}
			all[id] = true
			ids = append(ids, id)
			by[c][id] = e
			st, ok := e["status"].(string)
			if !ok || (st != "active" && st != "deprecated" && st != "reserved") {
				return bad("INVALID_STATUS", "invalid status")
			}
			if _, err := text(e, "spec", w); err != nil {
				return err
			}
			if _, err := text(e, "description", w); err != nil {
				return err
			}
			switch c {
			case "objects":
				if !exact(e, "id", "status", "spec", "description", "schema_version", "canonicalization", "digest", "schema") {
					return bad("INVALID_ENTRY", "bad object fields")
				}
				n, err := pos(e["schema_version"], "schema_version")
				if err != nil {
					return err
				}
				m := objRE.FindStringSubmatch(id)
				if m == nil || m[1] != fmt.Sprint(n) {
					return bad("INVALID_OBJECT_ID", "id/version mismatch")
				}
				for _, f := range []string{"canonicalization", "digest", "schema"} {
					if _, err := text(e, f, w); err != nil {
						return err
					}
				}
			case "canonicalization_algorithms":
				if !exact(e, "id", "status", "spec", "description", "receipt_version") {
					return bad("INVALID_ENTRY", "bad fields")
				}
				if _, err := pos(e["receipt_version"], "receipt_version"); err != nil {
					return err
				}
			case "digest_algorithms":
				if !exact(e, "id", "status", "spec", "description", "output_bits") {
					return bad("INVALID_ENTRY", "bad fields")
				}
				if _, err := pos(e["output_bits"], "output_bits"); err != nil {
					return err
				}
			case "signature_algorithms":
				if !exact(e, "id", "status", "spec", "description", "key_type", "signature_encoding") {
					return bad("INVALID_ENTRY", "bad fields")
				}
				if _, err := text(e, "key_type", w); err != nil {
					return err
				}
				if _, err := text(e, "signature_encoding", w); err != nil {
					return err
				}
			}
		}
		sorted := append([]string(nil), ids...)
		sort.Strings(sorted)
		for i := range ids {
			if ids[i] != sorted[i] {
				return bad("UNSORTED_COLLECTION", c+" unsorted")
			}
		}
	}
	xs := r["objects"].([]any)
	for _, rv := range xs {
		e := rv.(map[string]any)
		c := e["canonicalization"].(string)
		d := e["digest"].(string)
		ce, cok := by["canonicalization_algorithms"][c]
		de, dok := by["digest_algorithms"][d]
		if !cok || !dok {
			return bad("MISSING_REFERENCE", "missing reference")
		}
		if e["status"] == "active" && (ce["status"] == "reserved" || de["status"] == "reserved") {
			return bad("RESERVED_REFERENCE", "reserved reference")
		}
	}
	return nil
}
func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		os.Exit(2)
	}
	v, err := parseJSON(raw)
	if err == nil {
		err = validate(v)
	}
	r := Receipt{Accepted: err == nil}
	if err != nil {
		e := err.(*E)
		r.Detail = &e.detail
		r.ErrorCode = &e.code
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
	if err != nil {
		os.Exit(1)
	}
}
