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
