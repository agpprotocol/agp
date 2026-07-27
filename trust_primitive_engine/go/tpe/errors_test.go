package tpe

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorFormatting(t *testing.T) {
	err := &Error{
		Code:   CodeInvalidTrustPolicy,
		Detail: "missing policy_id",
		Path:   []string{"requirements", "0"},
	}
	const expected = "INVALID_TRUST_POLICY at requirements/0: missing policy_id"
	if got := err.Error(); got != expected {
		t.Fatalf("unexpected error text: got %q want %q", got, expected)
	}
}

func TestErrorIsMatchesByCode(t *testing.T) {
	err := WrapError(
		CodePolicyReferenceNotFound,
		"missing referenced policy",
		errors.New("lookup failed"),
	)
	if !errors.Is(err, &Error{Code: CodePolicyReferenceNotFound}) {
		t.Fatal("errors.Is did not match equal TPE code")
	}
	if errors.Is(err, &Error{Code: CodePolicyDigestMismatch}) {
		t.Fatal("errors.Is matched different TPE code")
	}
}

func TestErrorAsAndUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := fmt.Errorf("outer: %w", WrapError(CodeInvalidJSON, "decode failed", cause))
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatal("errors.As did not recover *tpe.Error")
	}
	if typed.Code != CodeInvalidJSON {
		t.Fatalf("unexpected code: %q", typed.Code)
	}
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause was not preserved")
	}
}

func TestErrorCode(t *testing.T) {
	code, ok := ErrorCode(NewError(CodeUnknownKey, "not found"))
	if !ok || code != CodeUnknownKey {
		t.Fatalf("unexpected extraction: code=%q ok=%v", code, ok)
	}
	if _, ok := ErrorCode(errors.New("plain")); ok {
		t.Fatal("plain error unexpectedly produced a TPE code")
	}
}
