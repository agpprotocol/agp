package evidence

import (
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	TypePresent = "evidence_present"
	TypeCount   = "evidence_count_at_least"
)

func optionalString(
	requirement map[string]any,
	field string,
) (string, bool, error) {
	value, present := requirement[field]
	if !present {
		return "", false, nil
	}
	result, err := parser.AsString(value, field)
	return result, true, err
}

func EvaluatePresent(
	requirement map[string]any,
	ctx model.Context,
) (map[string]any, string, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, "", err
	}
	evidenceID, err := parser.AsString(
		requirement["evidence_id"],
		"evidence_id",
	)
	if err != nil {
		return nil, "", err
	}
	expectedDigest, hasDigest, err := optionalString(requirement, "digest")
	if err != nil {
		return nil, "", err
	}
	expectedMediaType, hasMediaType, err := optionalString(
		requirement,
		"media_type",
	)
	if err != nil {
		return nil, "", err
	}

	matches := make([]model.Evidence, 0, 1)
	for _, entry := range ctx.Evidence {
		if entry.ID == evidenceID {
			matches = append(matches, entry)
		}
	}

	status := "absent"
	present := false
	var observedDigest any
	var observedMediaType any

	if len(matches) == 1 {
		entry := matches[0]
		present = true
		observedDigest = entry.Digest
		observedMediaType = entry.MediaType

		digestMismatch := hasDigest && entry.Digest != expectedDigest
		mediaTypeMismatch := hasMediaType &&
			entry.MediaType != expectedMediaType

		switch {
		case digestMismatch && mediaTypeMismatch:
			status = "digest_and_media_type_mismatch"
		case digestMismatch:
			status = "digest_mismatch"
		case mediaTypeMismatch:
			status = "media_type_mismatch"
		default:
			status = "matched"
		}
	}

	expected := map[string]any{"evidence_id": evidenceID}
	if hasDigest {
		expected["digest"] = expectedDigest
	}
	if hasMediaType {
		expected["media_type"] = expectedMediaType
	}

	failure := ""
	var failureValue any
	resultStatus := "satisfied"
	if status != "matched" {
		resultStatus = "unsatisfied"
		failure = "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED"
		failureValue = failure
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypePresent,
		"status":          resultStatus,
		"matched_signers": []string{},
		"observed": map[string]any{
			"evidence_id":  evidenceID,
			"match_status": status,
			"present":      present,
			"digest":       observedDigest,
			"media_type":   observedMediaType,
		},
		"expected":     expected,
		"failure_code": failureValue,
	}, failure, nil
}

func EvaluateCount(
	requirement map[string]any,
	ctx model.Context,
) (map[string]any, string, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, "", err
	}
	minimum, err := parser.AsInt(requirement["minimum"], "minimum")
	if err != nil {
		return nil, "", err
	}
	mediaType, hasMediaType, err := optionalString(requirement, "media_type")
	if err != nil {
		return nil, "", err
	}

	mediaTypesByID := map[string]map[string]struct{}{}
	for _, entry := range ctx.Evidence {
		if entry.ID == "" {
			continue
		}
		bucket, exists := mediaTypesByID[entry.ID]
		if !exists {
			bucket = map[string]struct{}{}
			mediaTypesByID[entry.ID] = bucket
		}
		if entry.MediaType != "" {
			bucket[entry.MediaType] = struct{}{}
		}
	}

	evidenceIDs := make([]string, 0, len(mediaTypesByID))
	for evidenceID, mediaTypes := range mediaTypesByID {
		if hasMediaType {
			if _, present := mediaTypes[mediaType]; !present {
				continue
			}
		}
		evidenceIDs = append(evidenceIDs, evidenceID)
	}
	sort.Strings(evidenceIDs)

	var expectedMediaType any
	if hasMediaType {
		expectedMediaType = mediaType
	}

	failure := ""
	var failureValue any
	resultStatus := "satisfied"
	if len(evidenceIDs) < minimum {
		resultStatus = "unsatisfied"
		failure = "EVIDENCE_COUNT_NOT_REACHED"
		failureValue = failure
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeCount,
		"status":          resultStatus,
		"matched_signers": []string{},
		"observed": map[string]any{
			"count":        len(evidenceIDs),
			"evidence_ids": evidenceIDs,
		},
		"expected": map[string]any{
			"minimum":    minimum,
			"media_type": expectedMediaType,
		},
		"failure_code": failureValue,
	}, failure, nil
}
