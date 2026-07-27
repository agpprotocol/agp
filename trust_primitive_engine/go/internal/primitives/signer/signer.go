package signer

import (
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	TypeRequired   = "required_signer"
	TypeThreshold  = "signer_threshold"
	TypeProhibited = "prohibited_signer"
	TypeAnyOf      = "any_of_signers"
	TypeAllOf      = "all_of_signers"
	TypeExactlyOne = "exactly_one_of_signers"
	TypeAtLeast    = "at_least_n_signers"
	TypeAtMost     = "at_most_n_signers"
	TypeExactlyN   = "exactly_n_signers"
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

func signerMatches(
	signerIDs []string,
	matchedSigners []string,
) []string {
	matchedState := matchedSet(matchedSigners)
	matched := make([]string, 0, len(signerIDs))
	for _, signerID := range signerIDs {
		if _, ok := matchedState[signerID]; ok {
			matched = append(matched, signerID)
		}
	}
	return matched
}

func EvaluateProhibited(
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
	status := "satisfied"
	var failure any
	if present {
		matched = []string{signerID}
		status = "unsatisfied"
		failure = "PROHIBITED_SIGNER_PRESENT"
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeProhibited,
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

func EvaluateAnyOf(
	requirement map[string]any,
	matchedSigners []string,
) (map[string]any, error) {
	return evaluateSignerSet(requirement, matchedSigners, TypeAnyOf)
}

func EvaluateAllOf(
	requirement map[string]any,
	matchedSigners []string,
) (map[string]any, error) {
	return evaluateSignerSet(requirement, matchedSigners, TypeAllOf)
}

func EvaluateExactlyOne(
	requirement map[string]any,
	matchedSigners []string,
) (map[string]any, error) {
	return evaluateSignerSet(requirement, matchedSigners, TypeExactlyOne)
}

func evaluateSignerSet(
	requirement map[string]any,
	matchedSigners []string,
	primitiveType string,
) (map[string]any, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, err
	}
	signerIDs, err := parser.AsStrings(requirement["signer_ids"], "signer_ids")
	if err != nil {
		return nil, err
	}

	matched := signerMatches(signerIDs, matchedSigners)
	status := "satisfied"
	var failure any
	observed := map[string]any{"matched_count": len(matched)}
	var expected map[string]any

	switch primitiveType {
	case TypeAnyOf:
		expected = map[string]any{
			"minimum_matches": 1,
			"signer_ids":      signerIDs,
		}
		if len(matched) == 0 {
			status = "unsatisfied"
			failure = "ANY_OF_SIGNERS_MISSING"
		}

	case TypeAllOf:
		matchedState := matchedSet(matchedSigners)
		missing := []string{}
		for _, signerID := range signerIDs {
			if _, ok := matchedState[signerID]; !ok {
				missing = append(missing, signerID)
			}
		}
		observed["missing_signer_ids"] = missing
		expected = map[string]any{
			"required_count": len(signerIDs),
			"signer_ids":     signerIDs,
		}
		if len(missing) != 0 {
			status = "unsatisfied"
			failure = "ALL_OF_SIGNERS_NOT_SATISFIED"
		}

	case TypeExactlyOne:
		expected = map[string]any{
			"exact_matches": 1,
			"signer_ids":    signerIDs,
		}
		if len(matched) != 1 {
			status = "unsatisfied"
			failure = "EXACTLY_ONE_OF_SIGNERS_NOT_SATISFIED"
		}
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            primitiveType,
		"status":          status,
		"matched_signers": matched,
		"observed":        observed,
		"expected":        expected,
		"failure_code":    failure,
	}, nil
}

func EvaluateAtLeast(
	requirement map[string]any,
	matchedSigners []string,
) (map[string]any, error) {
	return evaluateSignerCardinality(
		requirement,
		matchedSigners,
		TypeAtLeast,
		"minimum_matches",
	)
}

func EvaluateAtMost(
	requirement map[string]any,
	matchedSigners []string,
) (map[string]any, error) {
	return evaluateSignerCardinality(
		requirement,
		matchedSigners,
		TypeAtMost,
		"maximum_matches",
	)
}

func EvaluateExactlyN(
	requirement map[string]any,
	matchedSigners []string,
) (map[string]any, error) {
	return evaluateSignerCardinality(
		requirement,
		matchedSigners,
		TypeExactlyN,
		"exact_matches",
	)
}

func evaluateSignerCardinality(
	requirement map[string]any,
	matchedSigners []string,
	primitiveType string,
	limitField string,
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
	limit, err := parser.AsInt(requirement[limitField], limitField)
	if err != nil {
		return nil, err
	}

	matched := signerMatches(signerIDs, matchedSigners)
	status := "satisfied"
	var failure any

	switch primitiveType {
	case TypeAtLeast:
		if len(matched) < limit {
			status = "unsatisfied"
			failure = "AT_LEAST_N_SIGNERS_NOT_REACHED"
		}
	case TypeAtMost:
		if len(matched) > limit {
			status = "unsatisfied"
			failure = "AT_MOST_N_SIGNERS_EXCEEDED"
		}
	case TypeExactlyN:
		if len(matched) != limit {
			status = "unsatisfied"
			failure = "EXACTLY_N_SIGNERS_NOT_SATISFIED"
		}
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            primitiveType,
		"status":          status,
		"matched_signers": matched,
		"observed": map[string]any{
			"matched_count": len(matched),
		},
		"expected": map[string]any{
			limitField:   limit,
			"signer_ids": signerIDs,
		},
		"failure_code": failure,
	}, nil
}
