package tpe_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/tpe"
)

var (
	_ func(
		tpe.EvaluationInput,
		tpe.Policy,
		[]tpe.Policy,
	) (tpe.Evaluation, error) = tpe.Evaluate

	_ func(
		[]byte,
		[]byte,
		tpe.Policy,
		[]tpe.Policy,
	) (tpe.Evaluation, error) = tpe.EvaluateSigned

	_ func(error) (tpe.Code, bool)             = tpe.ErrorCode
	_ func(tpe.Code, string) *tpe.Error        = tpe.NewError
	_ func(tpe.Code, string, error) *tpe.Error = tpe.WrapError
)

func TestPublicTypesRemainAvailable(t *testing.T) {
	values := []any{
		tpe.Policy{},
		tpe.PolicyBinding{},
		tpe.Proposal{},
		tpe.Participant{},
		tpe.Evidence{},
		tpe.Context{},
		tpe.SignatureStatement{},
		tpe.Signature{},
		tpe.EvaluationInput{},
		tpe.Evaluation{},
		tpe.Error{},
		tpe.Code("TEST"),
	}

	for _, value := range values {
		typ := reflect.TypeOf(value)
		if typ == nil {
			t.Fatal("public type unexpectedly unavailable")
		}
		if strings.Contains(typ.PkgPath(), "/internal/") {
			t.Fatalf(
				"public type exposes internal package: %s",
				typ.PkgPath(),
			)
		}
	}
}

func TestEvaluationInputJSONContract(t *testing.T) {
	assertJSONFields(
		t,
		reflect.TypeOf(tpe.EvaluationInput{}),
		map[string]string{
			"ObjectType":    "object_type",
			"ContextDigest": "context_digest",
			"Context":       "context",
			"Signatures":    "signatures",
		},
	)
}

func TestEvaluationJSONContract(t *testing.T) {
	assertJSONFields(
		t,
		reflect.TypeOf(tpe.Evaluation{}),
		map[string]string{
			"ObjectType":            "object_type",
			"Status":                "status",
			"PolicyID":              "policy_id",
			"PolicyVersion":         "policy_version",
			"PolicyDigest":          "policy_digest",
			"ContextID":             "context_id",
			"ContextDigest":         "context_digest",
			"VerifiedSignatureIDs":  "verified_signature_ids",
			"VerifiedSigners":       "verified_signers",
			"MatchedSigners":        "matched_signers",
			"UnauthorizedSigners":   "unauthorized_signers",
			"IneligibleRoleSigners": "ineligible_role_signers",
			"SignatureCount":        "signature_count",
			"Weight":                "weight",
			"RequirementResults":    "requirement_results",
			"FailureCodes":          "failure_codes",
		},
	)
}

func TestPublicErrorsRemainTyped(t *testing.T) {
	inner := errors.New("inner")
	err := tpe.WrapError(
		tpe.CodeInvalidJSON,
		"invalid document",
		inner,
	)

	code, ok := tpe.ErrorCode(err)
	if !ok || code != tpe.CodeInvalidJSON {
		t.Fatalf("unexpected error code: %q ok=%v", code, ok)
	}

	if !errors.Is(err, inner) {
		t.Fatal("wrapped public error lost its cause")
	}
}

func assertJSONFields(
	t *testing.T,
	typ reflect.Type,
	expected map[string]string,
) {
	t.Helper()

	if typ.NumField() != len(expected) {
		t.Fatalf(
			"%s field count changed: got=%d expected=%d",
			typ.Name(),
			typ.NumField(),
			len(expected),
		)
	}

	for fieldName, expectedTag := range expected {
		field, ok := typ.FieldByName(fieldName)
		if !ok {
			t.Fatalf(
				"%s missing public field %s",
				typ.Name(),
				fieldName,
			)
		}

		actualTag := strings.Split(
			field.Tag.Get("json"),
			",",
		)[0]

		if actualTag != expectedTag {
			t.Fatalf(
				"%s.%s json tag=%q expected=%q",
				typ.Name(),
				fieldName,
				actualTag,
				expectedTag,
			)
		}

		if strings.Contains(field.Type.PkgPath(), "/internal/") {
			t.Fatalf(
				"%s.%s exposes internal type %s",
				typ.Name(),
				fieldName,
				field.Type,
			)
		}
	}
}
