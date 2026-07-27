package role

import (
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	TypeThreshold       = "role_threshold"
	TypeWeightThreshold = "role_weight_threshold"
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
