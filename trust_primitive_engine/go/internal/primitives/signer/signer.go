package signer

import (
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	TypeRequired  = "required_signer"
	TypeThreshold = "signer_threshold"
)

func matchedSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func EvaluateRequired(
	requirement map[string]any,
	matchedSigners []string,
) (map[string]any, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, err
	}
	signerID, err := parser.AsString(requirement["signer_id"], "signer_id")
	if err != nil {
		return nil, err
	}

	_, present := matchedSet(matchedSigners)[signerID]
	matched := []string{}
	status := "unsatisfied"
	var failure any = "REQUIRED_SIGNER_MISSING"
	if present {
		matched = []string{signerID}
		status = "satisfied"
		failure = nil
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeRequired,
		"status":          status,
		"matched_signers": matched,
		"observed": map[string]any{
			"present": present,
		},
		"expected": map[string]any{
			"signer_id": signerID,
		},
		"failure_code": failure,
	}, nil
}

func EvaluateThreshold(
	requirement map[string]any,
	matchedSigners []string,
) (map[string]any, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, err
	}
	signerIDs, err := parser.AsStrings(
		requirement["signer_ids"],
		"signer_ids",
	)
	if err != nil {
		return nil, err
	}
	minimum, err := parser.AsInt(
		requirement["minimum_signatures"],
		"minimum_signatures",
	)
	if err != nil {
		return nil, err
	}

	allowed := matchedSet(signerIDs)
	matched := []string{}
	for _, signerID := range matchedSigners {
		if _, ok := allowed[signerID]; ok {
			matched = append(matched, signerID)
		}
	}
	sort.Strings(matched)

	status := "satisfied"
	var failure any
	if len(matched) < minimum {
		status = "unsatisfied"
		failure = "SIGNER_THRESHOLD_NOT_REACHED"
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeThreshold,
		"status":          status,
		"matched_signers": matched,
		"observed": map[string]any{
			"signature_count": len(matched),
		},
		"expected": map[string]any{
			"minimum_signatures": minimum,
			"signer_ids":         signerIDs,
		},
		"failure_code": failure,
	}, nil
}
