package provenance

import (
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	TypeIssuerIn       = "evidence_issuer_in"
	TypeEvidenceIn     = "evidence_type_in"
	TypeDistinctIssuer = "evidence_distinct_issuers_at_least"
)

func optionalStrings(
	requirement map[string]any,
	field string,
) ([]string, bool, error) {
	value, present := requirement[field]
	if !present {
		return nil, false, nil
	}
	result, err := parser.AsStrings(value, field)
	return result, true, err
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func filteredEvidence(
	ctx model.Context,
	issuerIDs []string,
	filterIssuer bool,
	evidenceTypes []string,
	filterType bool,
) []model.Evidence {
	unique := map[string]model.Evidence{}
	for _, entry := range ctx.Evidence {
		if entry.ID == "" || entry.IssuerID == "" || entry.EvidenceType == "" {
			continue
		}
		if _, exists := unique[entry.ID]; !exists {
			unique[entry.ID] = entry
		}
	}

	ids := make([]string, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	result := make([]model.Evidence, 0, len(ids))
	for _, id := range ids {
		entry := unique[id]
		if filterIssuer && !contains(issuerIDs, entry.IssuerID) {
			continue
		}
		if filterType && !contains(evidenceTypes, entry.EvidenceType) {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func provenanceStatus(ctx model.Context) string {
	if ctx.ObjectType == "agp.decision-context/3" {
		return "available"
	}
	return "unavailable"
}

func observedEntries(
	status string,
	entries []model.Evidence,
) map[string]any {
	evidenceIDs := make([]string, 0, len(entries))
	issuerIDs := make([]string, 0, len(entries))
	evidenceTypes := make([]string, 0, len(entries))
	for _, entry := range entries {
		evidenceIDs = append(evidenceIDs, entry.ID)
		issuerIDs = append(issuerIDs, entry.IssuerID)
		evidenceTypes = append(evidenceTypes, entry.EvidenceType)
	}
	return map[string]any{
		"provenance_status": status,
		"evidence_ids":      uniqueSorted(evidenceIDs),
		"issuer_ids":        uniqueSorted(issuerIDs),
		"evidence_types":    uniqueSorted(evidenceTypes),
	}
}

// EvaluateIssuerIn evaluates evidence_issuer_in.
func EvaluateIssuerIn(
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
	issuerIDs, err := parser.AsStrings(
		requirement["issuer_ids"],
		"issuer_ids",
	)
	if err != nil {
		return nil, "", err
	}
	evidenceTypes, hasTypes, err := optionalStrings(
		requirement,
		"evidence_types",
	)
	if err != nil {
		return nil, "", err
	}

	status := provenanceStatus(ctx)
	entries := []model.Evidence{}
	if status == "available" {
		entries = filteredEvidence(
			ctx,
			issuerIDs,
			true,
			evidenceTypes,
			hasTypes,
		)
	}
	satisfied := status == "available" && len(entries) > 0
	failure := ""
	var failureValue any
	resultStatus := "satisfied"
	if !satisfied {
		resultStatus = "unsatisfied"
		failure = "EVIDENCE_ISSUER_NOT_ALLOWED"
		failureValue = failure
	}

	var expectedTypes any
	if hasTypes {
		expectedTypes = evidenceTypes
	}
	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeIssuerIn,
		"status":          resultStatus,
		"matched_signers": []string{},
		"observed":        observedEntries(status, entries),
		"expected": map[string]any{
			"issuer_ids":     issuerIDs,
			"evidence_types": expectedTypes,
		},
		"failure_code": failureValue,
	}, failure, nil
}

// EvaluateEvidenceTypeIn evaluates evidence_type_in.
func EvaluateEvidenceTypeIn(
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
	evidenceTypes, err := parser.AsStrings(
		requirement["evidence_types"],
		"evidence_types",
	)
	if err != nil {
		return nil, "", err
	}
	issuerIDs, hasIssuers, err := optionalStrings(
		requirement,
		"issuer_ids",
	)
	if err != nil {
		return nil, "", err
	}

	status := provenanceStatus(ctx)
	entries := []model.Evidence{}
	if status == "available" {
		entries = filteredEvidence(
			ctx,
			issuerIDs,
			hasIssuers,
			evidenceTypes,
			true,
		)
	}
	satisfied := status == "available" && len(entries) > 0
	failure := ""
	var failureValue any
	resultStatus := "satisfied"
	if !satisfied {
		resultStatus = "unsatisfied"
		failure = "EVIDENCE_TYPE_NOT_ALLOWED"
		failureValue = failure
	}

	var expectedIssuers any
	if hasIssuers {
		expectedIssuers = issuerIDs
	}
	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeEvidenceIn,
		"status":          resultStatus,
		"matched_signers": []string{},
		"observed":        observedEntries(status, entries),
		"expected": map[string]any{
			"evidence_types": evidenceTypes,
			"issuer_ids":     expectedIssuers,
		},
		"failure_code": failureValue,
	}, failure, nil
}

// EvaluateDistinctIssuers evaluates evidence_distinct_issuers_at_least.
func EvaluateDistinctIssuers(
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
	evidenceTypes, hasTypes, err := optionalStrings(
		requirement,
		"evidence_types",
	)
	if err != nil {
		return nil, "", err
	}

	status := provenanceStatus(ctx)
	entries := []model.Evidence{}
	if status == "available" {
		entries = filteredEvidence(
			ctx,
			nil,
			false,
			evidenceTypes,
			hasTypes,
		)
	}
	issuerIDs := make([]string, 0, len(entries))
	evidenceIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		issuerIDs = append(issuerIDs, entry.IssuerID)
		evidenceIDs = append(evidenceIDs, entry.ID)
	}
	issuerIDs = uniqueSorted(issuerIDs)
	evidenceIDs = uniqueSorted(evidenceIDs)

	satisfied := status == "available" && len(issuerIDs) >= minimum
	failure := ""
	var failureValue any
	resultStatus := "satisfied"
	if !satisfied {
		resultStatus = "unsatisfied"
		failure = "EVIDENCE_DISTINCT_ISSUER_MINIMUM_NOT_REACHED"
		failureValue = failure
	}

	var expectedTypes any
	if hasTypes {
		expectedTypes = evidenceTypes
	}
	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeDistinctIssuer,
		"status":          resultStatus,
		"matched_signers": []string{},
		"observed": map[string]any{
			"provenance_status": status,
			"count":             len(issuerIDs),
			"issuer_ids":        issuerIDs,
			"evidence_ids":      evidenceIDs,
		},
		"expected": map[string]any{
			"minimum":        minimum,
			"evidence_types": expectedTypes,
		},
		"failure_code": failureValue,
	}, failure, nil
}
