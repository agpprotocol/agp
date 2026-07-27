package role

import (
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	TypeThreshold       = "role_threshold"
	TypeWeightThreshold = "role_weight_threshold"
	TypeGlobalThreshold = "global_signature_threshold"
	TypeGlobalWeight    = "global_weight_threshold"
	TypeSeparation      = "separation_of_duties"
)

func matchedForRole(
	ctx model.Context,
	matchedSigners []string,
	requiredRole string,
) ([]string, int) {
	participants := make(map[string]model.Participant, len(ctx.Participants))
	for _, participant := range ctx.Participants {
		participants[participant.ID] = participant
	}

	matched := make([]string, 0, len(matchedSigners))
	weight := 0
	for _, signerID := range matchedSigners {
		participant, present := participants[signerID]
		if !present || participant.Role != requiredRole {
			continue
		}
		matched = append(matched, signerID)
		weight += participant.Weight
	}
	sort.Strings(matched)
	return matched, weight
}

func EvaluateThreshold(
	requirement map[string]any,
	ctx model.Context,
	matchedSigners []string,
) (map[string]any, error) {
	requirementID, err := parser.AsString(requirement["requirement_id"], "requirement_id")
	if err != nil {
		return nil, err
	}
	requiredRole, err := parser.AsString(requirement["role"], "role")
	if err != nil {
		return nil, err
	}
	minimum, err := parser.AsInt(requirement["minimum_signatures"], "minimum_signatures")
	if err != nil {
		return nil, err
	}

	matched, _ := matchedForRole(ctx, matchedSigners, requiredRole)
	status := "satisfied"
	var failure any
	if len(matched) < minimum {
		status = "unsatisfied"
		failure = "ROLE_THRESHOLD_NOT_REACHED"
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeThreshold,
		"status":          status,
		"matched_signers": matched,
		"observed": map[string]any{
			"role":            requiredRole,
			"signature_count": len(matched),
		},
		"expected": map[string]any{
			"role":               requiredRole,
			"minimum_signatures": minimum,
		},
		"failure_code": failure,
	}, nil
}

func EvaluateWeightThreshold(
	requirement map[string]any,
	ctx model.Context,
	matchedSigners []string,
) (map[string]any, error) {
	requirementID, err := parser.AsString(requirement["requirement_id"], "requirement_id")
	if err != nil {
		return nil, err
	}
	requiredRole, err := parser.AsString(requirement["role"], "role")
	if err != nil {
		return nil, err
	}
	minimum, err := parser.AsInt(requirement["minimum_weight"], "minimum_weight")
	if err != nil {
		return nil, err
	}

	matched, weight := matchedForRole(ctx, matchedSigners, requiredRole)
	status := "satisfied"
	var failure any
	if weight < minimum {
		status = "unsatisfied"
		failure = "ROLE_WEIGHT_THRESHOLD_NOT_REACHED"
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeWeightThreshold,
		"status":          status,
		"matched_signers": matched,
		"observed": map[string]any{
			"role":   requiredRole,
			"weight": weight,
		},
		"expected": map[string]any{
			"role":           requiredRole,
			"minimum_weight": minimum,
		},
		"failure_code": failure,
	}, nil
}

func EvaluateGlobalThreshold(
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
	minimum, err := parser.AsInt(
		requirement["minimum_signatures"],
		"minimum_signatures",
	)
	if err != nil {
		return nil, err
	}

	matched := append([]string(nil), matchedSigners...)
	sort.Strings(matched)
	status := "satisfied"
	var failure any
	if len(matched) < minimum {
		status = "unsatisfied"
		failure = "GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED"
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeGlobalThreshold,
		"status":          status,
		"matched_signers": matched,
		"observed": map[string]any{
			"signature_count": len(matched),
		},
		"expected": map[string]any{
			"minimum_signatures": minimum,
		},
		"failure_code": failure,
	}, nil
}

func EvaluateGlobalWeight(
	requirement map[string]any,
	ctx model.Context,
	matchedSigners []string,
) (map[string]any, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, err
	}
	minimum, err := parser.AsInt(
		requirement["minimum_weight"],
		"minimum_weight",
	)
	if err != nil {
		return nil, err
	}

	participants := make(map[string]model.Participant, len(ctx.Participants))
	for _, participant := range ctx.Participants {
		participants[participant.ID] = participant
	}

	matched := append([]string(nil), matchedSigners...)
	sort.Strings(matched)
	weight := 0
	for _, signerID := range matched {
		if participant, present := participants[signerID]; present {
			weight += participant.Weight
		}
	}

	status := "satisfied"
	var failure any
	if weight < minimum {
		status = "unsatisfied"
		failure = "GLOBAL_WEIGHT_THRESHOLD_NOT_REACHED"
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeGlobalWeight,
		"status":          status,
		"matched_signers": matched,
		"observed": map[string]any{
			"weight": weight,
		},
		"expected": map[string]any{
			"minimum_weight": minimum,
		},
		"failure_code": failure,
	}, nil
}

func EvaluateSeparationOfDuties(
	requirement map[string]any,
	ctx model.Context,
	matchedSigners []string,
) (map[string]any, error) {
	requirementID, err := parser.AsString(requirement["requirement_id"], "requirement_id")
	if err != nil {
		return nil, err
	}
	roles, err := parser.AsStrings(requirement["roles"], "roles")
	if err != nil {
		return nil, err
	}

	participants := make(map[string]model.Participant, len(ctx.Participants))
	for _, participant := range ctx.Participants {
		participants[participant.ID] = participant
	}

	matchedByRole := make(map[string][]string, len(roles))
	for _, requiredRole := range roles {
		matchedByRole[requiredRole] = []string{}
	}
	for _, signerID := range matchedSigners {
		participant, present := participants[signerID]
		if !present {
			continue
		}
		if _, required := matchedByRole[participant.Role]; required {
			matchedByRole[participant.Role] = append(matchedByRole[participant.Role], signerID)
		}
	}

	matched := []string{}
	presentRoles := []string{}
	missingRoles := []string{}
	for _, requiredRole := range roles {
		roleMatched := matchedByRole[requiredRole]
		sort.Strings(roleMatched)
		matched = append(matched, roleMatched...)
		if len(roleMatched) == 0 {
			missingRoles = append(missingRoles, requiredRole)
		} else {
			presentRoles = append(presentRoles, requiredRole)
		}
	}
	sort.Strings(matched)

	status := "satisfied"
	var failure any
	if len(missingRoles) != 0 {
		status = "unsatisfied"
		failure = "SEPARATION_OF_DUTIES_NOT_SATISFIED"
	}

	return map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeSeparation,
		"status":          status,
		"matched_signers": matched,
		"observed":        map[string]any{"present_roles": presentRoles, "missing_roles": missingRoles},
		"expected":        map[string]any{"roles": roles, "distinct_identities": 2},
		"failure_code":    failure,
	}, nil
}
