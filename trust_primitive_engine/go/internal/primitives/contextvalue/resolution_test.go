package contextvalue

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func resolutionContext() model.Context {
	return model.Context{
		Proposal: model.Proposal{
			Payload: map[string]any{
				"service": "payments",
				"enabled": true,
				"limit":   json.Number("9007199254740991"),
				"nested": map[string]any{
					"a/b": "slash",
					"a~b": "tilde",
				},
				"items": []any{
					map[string]any{"name": "first"},
					"second",
				},
				"container": map[string]any{"key": "value"},
				"null":      nil,
			},
		},
	}
}

func TestParsePathCanonicalRules(t *testing.T) {
	segments, err := ParsePath("/proposal/payload/nested/a~1b")
	if err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
	if !reflect.DeepEqual(segments, []string{"nested", "a/b"}) {
		t.Fatalf("unexpected segments: %#v", segments)
	}

	invalid := []string{
		"/proposal/payload/",
		"/proposal/payload/items/01",
		"/proposal/payload/items/-1",
		"/proposal/payload/items/-",
		"/proposal/payload/nested/a~2b",
		"/proposal/payload/nested/a~",
		"/proposal/payload//name",
		"/other/payload/name",
		"/proposal/payload/" + strings.Repeat("x", 500),
	}
	for _, path := range invalid {
		if _, err := ParsePath(path); err == nil {
			t.Fatalf("invalid path accepted: %q", path)
		}
	}
}

func TestResolvePathStatusesAndTypes(t *testing.T) {
	ctx := resolutionContext()
	tests := []struct {
		path      string
		status    string
		valueType string
		value     any
	}{
		{"/proposal/payload/service", "found", "string", "payments"},
		{"/proposal/payload/enabled", "found", "boolean", true},
		{"/proposal/payload/limit", "found", "integer", int64(9007199254740991)},
		{"/proposal/payload/null", "found", "null", nil},
		{"/proposal/payload/container", "found", "object", nil},
		{"/proposal/payload/items", "found", "array", nil},
		{"/proposal/payload/items/0/name", "found", "string", "first"},
		{"/proposal/payload/items/3", "missing", "", nil},
		{"/proposal/payload/missing", "missing", "", nil},
		{"/proposal/payload/service/name", "type_mismatch", "", nil},
		{"/proposal/payload/items/name", "type_mismatch", "", nil},
		{"/proposal/payload/nested/a~0b", "found", "string", "tilde"},
	}

	for _, test := range tests {
		result, err := ResolvePath(ctx, test.path)
		if err != nil {
			t.Fatalf("%s: resolve failed: %v", test.path, err)
		}
		if result.Status != test.status ||
			result.ValueType != test.valueType ||
			!reflect.DeepEqual(result.Value, test.value) {
			t.Fatalf(
				"%s: got %#v want status=%q type=%q value=%#v",
				test.path,
				result,
				test.status,
				test.valueType,
				test.value,
			)
		}
	}
}

func TestResolvePathMissingPayload(t *testing.T) {
	result, err := ResolvePath(
		model.Context{},
		"/proposal/payload/service",
	)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if result.Status != "missing" {
		t.Fatalf("unexpected result: %#v", result)
	}
}
