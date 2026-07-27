package evidence

import (
	"reflect"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func evidenceContext() model.Context {
	return model.Context{
		Evidence: []model.Evidence{
			{
				ID:        "evidence:a",
				Digest:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				MediaType: "application/json",
			},
			{
				ID:        "evidence:b",
				Digest:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				MediaType: "application/pdf",
			},
		},
	}
}

func TestEvaluatePresentMatched(t *testing.T) {
	result, failure, err := EvaluatePresent(
		map[string]any{
			"requirement_id": "requirement:present",
			"evidence_id":    "evidence:a",
			"digest":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"media_type":     "application/json",
		},
		evidenceContext(),
	)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if failure != "" || result["status"] != "satisfied" {
		t.Fatalf("unexpected result: %#v failure=%q", result, failure)
	}
	observed := result["observed"].(map[string]any)
	if observed["match_status"] != "matched" || observed["present"] != true {
		t.Fatalf("unexpected observation: %#v", observed)
	}
}

func TestEvaluatePresentMismatchAndAbsent(t *testing.T) {
	result, failure, err := EvaluatePresent(
		map[string]any{
			"requirement_id": "requirement:mismatch",
			"evidence_id":    "evidence:a",
			"digest":         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"media_type":     "application/pdf",
		},
		evidenceContext(),
	)
	if err != nil {
		t.Fatalf("evaluate mismatch: %v", err)
	}
	if failure != "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED" {
		t.Fatalf("unexpected failure: %q", failure)
	}
	observed := result["observed"].(map[string]any)
	if observed["match_status"] != "digest_and_media_type_mismatch" ||
		observed["present"] != true {
		t.Fatalf("unexpected mismatch observation: %#v", observed)
	}

	result, failure, err = EvaluatePresent(
		map[string]any{
			"requirement_id": "requirement:absent",
			"evidence_id":    "evidence:missing",
		},
		evidenceContext(),
	)
	if err != nil {
		t.Fatalf("evaluate absent: %v", err)
	}
	if failure != "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED" {
		t.Fatalf("unexpected absent failure: %q", failure)
	}
	observed = result["observed"].(map[string]any)
	if observed["match_status"] != "absent" ||
		observed["present"] != false ||
		observed["digest"] != nil ||
		observed["media_type"] != nil {
		t.Fatalf("unexpected absent observation: %#v", observed)
	}
}

func TestEvaluatePresentDuplicateIDFailsClosed(t *testing.T) {
	ctx := evidenceContext()
	ctx.Evidence = append(ctx.Evidence, ctx.Evidence[0])

	result, failure, err := EvaluatePresent(
		map[string]any{
			"requirement_id": "requirement:duplicate",
			"evidence_id":    "evidence:a",
		},
		ctx,
	)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if failure != "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED" {
		t.Fatalf("unexpected failure: %q", failure)
	}
	observed := result["observed"].(map[string]any)
	if observed["match_status"] != "absent" {
		t.Fatalf("duplicate ID did not fail closed: %#v", result)
	}
}

func TestEvaluateCountUniqueAndFiltered(t *testing.T) {
	ctx := evidenceContext()
	ctx.Evidence = append(
		ctx.Evidence,
		model.Evidence{ID: "evidence:a", MediaType: "application/pdf"},
		model.Evidence{ID: "evidence:c", MediaType: "application/json"},
	)

	result, failure, err := EvaluateCount(
		map[string]any{
			"requirement_id": "requirement:count",
			"minimum":        2,
			"media_type":     "application/json",
		},
		ctx,
	)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if failure != "" || result["status"] != "satisfied" {
		t.Fatalf("unexpected result: %#v failure=%q", result, failure)
	}
	observed := result["observed"].(map[string]any)
	if observed["count"] != 2 {
		t.Fatalf("unexpected count: %#v", observed)
	}
	if !reflect.DeepEqual(
		observed["evidence_ids"],
		[]string{"evidence:a", "evidence:c"},
	) {
		t.Fatalf("unexpected IDs: %#v", observed["evidence_ids"])
	}
}

func TestEvaluateCountUnsatisfiedAndNullFilter(t *testing.T) {
	result, failure, err := EvaluateCount(
		map[string]any{
			"requirement_id": "requirement:count",
			"minimum":        3,
		},
		evidenceContext(),
	)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if failure != "EVIDENCE_COUNT_NOT_REACHED" ||
		result["status"] != "unsatisfied" {
		t.Fatalf("unexpected result: %#v failure=%q", result, failure)
	}
	expected := result["expected"].(map[string]any)
	if expected["media_type"] != nil {
		t.Fatalf("missing filter was not null: %#v", expected)
	}
}
