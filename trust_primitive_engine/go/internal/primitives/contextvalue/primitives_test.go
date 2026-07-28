package contextvalue

import (
	"encoding/json"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func primitiveContext() model.Context {
	return model.Context{
		Proposal: model.Proposal{
			Payload: map[string]any{
				"environment": "production",
				"nullable":    nil,
				"enabled":     true,
				"coverage":    json.Number("9000"),
				"rollout":     json.Number("2500"),
				"object":      map[string]any{"name": "service"},
				"long":        string(make([]byte, 4097)),
			},
		},
	}
}

func TestEvaluateValuePresent(t *testing.T) {
	ctx := primitiveContext()
	for _, test := range []struct {
		path      string
		satisfied bool
		failure   string
	}{
		{"/proposal/payload/environment", true, ""},
		{"/proposal/payload/nullable", true, ""},
		{"/proposal/payload/object", true, ""},
		{"/proposal/payload/missing", false, "CONTEXT_VALUE_NOT_PRESENT"},
		{
			"/proposal/payload/environment/name",
			false,
			"CONTEXT_VALUE_NOT_PRESENT",
		},
	} {
		result, failure, err := EvaluateValuePresent(
			map[string]any{
				"requirement_id": "requirement:present",
				"path":           test.path,
			},
			ctx,
		)
		if err != nil {
			t.Fatalf("%s: evaluate: %v", test.path, err)
		}
		if (result["status"] == "satisfied") != test.satisfied ||
			failure != test.failure {
			t.Fatalf(
				"%s: unexpected result=%#v failure=%q",
				test.path,
				result,
				failure,
			)
		}
	}
}

func TestEvaluateValueEqualsStrict(t *testing.T) {
	ctx := primitiveContext()
	tests := []struct {
		path      string
		value     any
		satisfied bool
	}{
		{"/proposal/payload/environment", "production", true},
		{"/proposal/payload/environment", "staging", false},
		{"/proposal/payload/enabled", 1, false},
		{"/proposal/payload/nullable", nil, true},
		{"/proposal/payload/object", "service", false},
	}
	for _, test := range tests {
		result, failure, err := EvaluateValueEquals(
			map[string]any{
				"requirement_id": "requirement:equals",
				"path":           test.path,
				"value":          test.value,
			},
			ctx,
		)
		if err != nil {
			t.Fatalf("%s: evaluate: %v", test.path, err)
		}
		if (result["status"] == "satisfied") != test.satisfied {
			t.Fatalf("%s: unexpected result: %#v", test.path, result)
		}
		if !test.satisfied && failure != "CONTEXT_VALUE_NOT_EQUAL" {
			t.Fatalf("%s: unexpected failure: %q", test.path, failure)
		}
	}
}

func TestValidateScalarSetCanonicalRules(t *testing.T) {
	valid := []any{
		[]any{nil},
		[]any{false, true},
		[]any{json.Number("-2"), json.Number("0"), json.Number("7")},
		[]any{"alpha", "beta"},
	}
	for _, value := range valid {
		if err := ValidateScalarSet(value); err != nil {
			t.Fatalf("valid scalar set rejected %#v: %v", value, err)
		}
	}

	invalid := []any{
		[]any{},
		make([]any, 65),
		[]any{true, false},
		[]any{"beta", "alpha"},
		[]any{json.Number("1"), json.Number("1")},
		[]any{"one", json.Number("2")},
		[]any{map[string]any{"key": "value"}},
	}
	for _, value := range invalid {
		if err := ValidateScalarSet(value); err == nil {
			t.Fatalf("invalid scalar set accepted: %#v", value)
		}
	}
}

func TestEvaluateValueIn(t *testing.T) {
	ctx := primitiveContext()
	tests := []struct {
		path      string
		values    []any
		satisfied bool
	}{
		{
			"/proposal/payload/environment",
			[]any{"production", "staging"},
			true,
		},
		{
			"/proposal/payload/environment",
			[]any{"development", "staging"},
			false,
		},
		{
			"/proposal/payload/enabled",
			[]any{json.Number("1")},
			false,
		},
		{
			"/proposal/payload/missing",
			[]any{"production"},
			false,
		},
	}
	for _, test := range tests {
		result, failure, err := EvaluateValueIn(
			map[string]any{
				"requirement_id": "requirement:in",
				"path":           test.path,
				"values":         test.values,
			},
			ctx,
		)
		if err != nil {
			t.Fatalf("%s: evaluate: %v", test.path, err)
		}
		if (result["status"] == "satisfied") != test.satisfied {
			t.Fatalf("%s: unexpected result: %#v", test.path, result)
		}
		if !test.satisfied && failure != "CONTEXT_VALUE_NOT_IN_SET" {
			t.Fatalf("%s: unexpected failure: %q", test.path, failure)
		}
	}
}

func TestEvaluatePathEquals(t *testing.T) {
	ctx := primitiveContext()
	ctx.Proposal.Payload["requested"] = "3.0.0"
	ctx.Proposal.Payload["approved"] = "3.0.0"
	ctx.Proposal.Payload["numeric"] = json.Number("3")
	ctx.Proposal.Payload["container_two"] = map[string]any{"name": "service"}

	tests := []struct {
		left      string
		right     string
		satisfied bool
	}{
		{"/proposal/payload/requested", "/proposal/payload/approved", true},
		{"/proposal/payload/requested", "/proposal/payload/environment", false},
		{"/proposal/payload/requested", "/proposal/payload/numeric", false},
		{"/proposal/payload/object", "/proposal/payload/container_two", false},
		{"/proposal/payload/missing", "/proposal/payload/approved", false},
	}

	for _, test := range tests {
		result, failure, err := EvaluatePathEquals(
			map[string]any{
				"requirement_id": "requirement:path-equals",
				"left_path":      test.left,
				"right_path":     test.right,
			},
			ctx,
		)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if (result["status"] == "satisfied") != test.satisfied {
			t.Fatalf("unexpected result: %#v", result)
		}
		if !test.satisfied &&
			failure != "CONTEXT_PATH_VALUES_NOT_EQUAL" {
			t.Fatalf("unexpected failure: %q", failure)
		}
	}
}

func TestEvaluateIntegerBounds(t *testing.T) {
	ctx := primitiveContext()

	minimum, failure, err := EvaluateIntegerAtLeast(
		map[string]any{
			"requirement_id": "requirement:minimum",
			"path":           "/proposal/payload/coverage",
			"minimum":        json.Number("9000"),
		},
		ctx,
	)
	if err != nil || failure != "" || minimum["status"] != "satisfied" {
		t.Fatalf("unexpected minimum: %#v failure=%q err=%v", minimum, failure, err)
	}

	maximum, failure, err := EvaluateIntegerAtMost(
		map[string]any{
			"requirement_id": "requirement:maximum",
			"path":           "/proposal/payload/rollout",
			"maximum":        2499,
		},
		ctx,
	)
	if err != nil ||
		failure != "CONTEXT_INTEGER_MAXIMUM_EXCEEDED" ||
		maximum["status"] != "unsatisfied" {
		t.Fatalf("unexpected maximum: %#v failure=%q err=%v", maximum, failure, err)
	}

	boolean, failure, err := EvaluateIntegerAtLeast(
		map[string]any{
			"requirement_id": "requirement:boolean",
			"path":           "/proposal/payload/enabled",
			"minimum":        1,
		},
		ctx,
	)
	if err != nil ||
		failure != "CONTEXT_INTEGER_MINIMUM_NOT_REACHED" ||
		boolean["status"] != "unsatisfied" {
		t.Fatalf("unexpected boolean result: %#v failure=%q err=%v", boolean, failure, err)
	}
}

func TestObservationBoundsContainersAndLongStrings(t *testing.T) {
	ctx := primitiveContext()

	container, _, err := EvaluateValuePresent(
		map[string]any{
			"requirement_id": "requirement:object",
			"path":           "/proposal/payload/object",
		},
		ctx,
	)
	if err != nil {
		t.Fatalf("object evaluate: %v", err)
	}
	observed := container["observed"].(map[string]any)
	if observed["value_type"] != "object" || observed["value"] != nil {
		t.Fatalf("container copied into result: %#v", observed)
	}

	long, _, err := EvaluateValuePresent(
		map[string]any{
			"requirement_id": "requirement:long",
			"path":           "/proposal/payload/long",
		},
		ctx,
	)
	if err != nil {
		t.Fatalf("long evaluate: %v", err)
	}
	observed = long["observed"].(map[string]any)
	if observed["value_type"] != "string" || observed["value"] != nil {
		t.Fatalf("long string copied into result: %#v", observed)
	}
}
