package tpe

import (
	"errors"
	"fmt"
	"strings"
)

// Code is a stable machine-readable fatal TPE error code.
type Code string

const (
	CodeInvalidJSON                   Code = "INVALID_JSON"
	CodeInvalidTrustPolicy            Code = "INVALID_TRUST_POLICY"
	CodeInvalidTrustPolicySet         Code = "INVALID_TRUST_POLICY_SET"
	CodeUnsupportedTrustPrimitive     Code = "UNSUPPORTED_TRUST_PRIMITIVE"
	CodePolicyReferenceNotFound       Code = "POLICY_REFERENCE_NOT_FOUND"
	CodePolicyReferenceDigestMismatch Code = "POLICY_REFERENCE_DIGEST_MISMATCH"
	CodePolicyReferenceCycle          Code = "POLICY_REFERENCE_CYCLE"
	CodePolicyReferenceDepthExceeded  Code = "POLICY_REFERENCE_DEPTH_EXCEEDED"
	CodePolicyReferenceCountExceeded  Code = "POLICY_REFERENCE_COUNT_EXCEEDED"
	CodePolicyReferenceNodeLimit      Code = "POLICY_REFERENCE_NODE_LIMIT_EXCEEDED"
	CodeInvalidSignedDecisionContext  Code = "INVALID_SIGNED_DECISION_CONTEXT"
	CodeSignatureVerificationFailed   Code = "SIGNATURE_VERIFICATION_FAILED"
	CodeInvalidSignature              Code = "INVALID_SIGNATURE"
	CodeUnknownKey                    Code = "UNKNOWN_KEY"
	CodeUnsupportedAlgorithm          Code = "UNSUPPORTED_ALGORITHM"
	CodePolicyIDMismatch              Code = "POLICY_ID_MISMATCH"
	CodePolicyVersionMismatch         Code = "POLICY_VERSION_MISMATCH"
	CodePolicyDigestMismatch          Code = "POLICY_DIGEST_MISMATCH"
)

// Error is a typed fatal TPE error.
type Error struct {
	Code   Code
	Detail string
	Path   []string
	Cause  error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	prefix := string(e.Code)
	if len(e.Path) > 0 {
		prefix += " at " + strings.Join(e.Path, "/")
	}
	if e.Detail == "" {
		return prefix
	}
	return fmt.Sprintf("%s: %s", prefix, e.Detail)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *Error) Is(target error) bool {
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	return other.Code == "" || e.Code == other.Code
}

func NewError(code Code, detail string) *Error {
	return &Error{Code: code, Detail: detail}
}

func WrapError(code Code, detail string, cause error) *Error {
	return &Error{Code: code, Detail: detail, Cause: cause}
}

func ErrorCode(err error) (Code, bool) {
	var typed *Error
	if !errors.As(err, &typed) {
		return "", false
	}
	return typed.Code, true
}
