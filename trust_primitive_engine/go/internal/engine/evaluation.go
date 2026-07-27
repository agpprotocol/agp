package engine

import (
	"errors"
	"fmt"
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
	"agpprotocol.org/agp/trust-primitive-engine/internal/primitives/provenance"
	"agpprotocol.org/agp/trust-primitive-engine/internal/primitives/role"
	"agpprotocol.org/agp/trust-primitive-engine/internal/primitives/signer"
	"agpprotocol.org/agp/trust-primitive-engine/internal/validation"
)

const typePolicyRef = "policy_reference"

type projectedFailure struct {
	path          []string
	emissionIndex int
	failureCode   string
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

func findPolicy(
	policySet []model.Policy,
	id string,
	version int,
) (model.Policy, bool) {
	for _, candidate := range policySet {
		if candidate.PolicyID == id && candidate.Version == version {
			return candidate, true
		}
	}
	return model.Policy{}, false
}

func resultSatisfied(result map[string]any) bool {
	status, _ := result["status"].(string)
	return status == "satisfied"
}

func resultMatchedSigners(result map[string]any) []string {
	values, ok := result["matched_signers"].([]string)
	if ok {
		return append([]string(nil), values...)
	}
	raw, ok := result["matched_signers"].([]any)
	if !ok {
		return []string{}
	}
	values = make([]string, 0, len(raw))
	for _, item := range raw {
		if value, ok := item.(string); ok {
			values = append(values, value)
		}
	}
	return values
}

func aggregateChildMatchedSigners(children []any) []string {
	values := []string{}
	for _, rawChild := range children {
		child, ok := rawChild.(map[string]any)
		if !ok {
			continue
		}
		values = append(values, resultMatchedSigners(child)...)
	}
	return uniqueSorted(values)
}

func evaluateRequirementNode(
	requirement map[string]any,
	policySet []model.Policy,
	ctx model.Context,
	matchedSigners []string,
) (map[string]any, error) {
	primitiveType, err := parser.AsString(requirement["type"], "type")
	if err != nil {
		return nil, err
	}

	switch primitiveType {
	case signer.TypeRequired:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateRequired(requirement, matchedSigners)

	case signer.TypeThreshold:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateThreshold(requirement, matchedSigners)

	case signer.TypeProhibited:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateProhibited(requirement, matchedSigners)

	case signer.TypeAnyOf:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateAnyOf(requirement, matchedSigners)

	case signer.TypeAllOf:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateAllOf(requirement, matchedSigners)

	case signer.TypeExactlyOne:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateExactlyOne(requirement, matchedSigners)

	case signer.TypeAtLeast:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateAtLeast(requirement, matchedSigners)

	case signer.TypeAtMost:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateAtMost(requirement, matchedSigners)

	case signer.TypeExactlyN:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return signer.EvaluateExactlyN(requirement, matchedSigners)

	case role.TypeThreshold:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return role.EvaluateThreshold(requirement, ctx, matchedSigners)

	case role.TypeWeightThreshold:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		return role.EvaluateWeightThreshold(requirement, ctx, matchedSigners)

	case provenance.TypeIssuerIn:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		result, _, err := provenance.EvaluateIssuerIn(requirement, ctx)
		return result, err

	case provenance.TypeEvidenceIn:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		result, _, err := provenance.EvaluateEvidenceTypeIn(requirement, ctx)
		return result, err

	case provenance.TypeDistinctIssuer:
		if err := validation.ValidateRequirement(requirement); err != nil {
			return nil, err
		}
		result, _, err := provenance.EvaluateDistinctIssuers(requirement, ctx)
		return result, err

	case "all_of", "any_of":
		rawChildren, ok := requirement["requirements"].([]any)
		if !ok {
			return nil, errors.New(
				"composition requirements must be an array",
			)
		}

		children := make([]any, 0, len(rawChildren))
		satisfiedChildren := 0
		for _, rawChild := range rawChildren {
			child, ok := rawChild.(map[string]any)
			if !ok {
				return nil, errors.New(
					"composition child must be an object",
				)
			}
			childResult, innerErr := evaluateRequirementNode(
				child,
				policySet,
				ctx,
				matchedSigners,
			)
			if innerErr != nil {
				return nil, innerErr
			}
			if resultSatisfied(childResult) {
				satisfiedChildren++
			}
			children = append(children, childResult)
		}

		totalChildren := len(children)
		satisfied := satisfiedChildren == totalChildren
		expected := map[string]any{
			"required_satisfied_children": totalChildren,
		}
		failureCode := "ALL_OF_NOT_SATISFIED"

		if primitiveType == "any_of" {
			satisfied = satisfiedChildren >= 1
			expected = map[string]any{
				"minimum_satisfied_children": 1,
			}
			failureCode = "ANY_OF_NOT_SATISFIED"
		}

		status := "satisfied"
		var failureValue any
		if !satisfied {
			status = "unsatisfied"
			failureValue = failureCode
		}

		requirementID, err := parser.AsString(
			requirement["requirement_id"],
			"requirement_id",
		)
		if err != nil {
			return nil, err
		}

		return map[string]any{
			"requirement_id":  requirementID,
			"type":            primitiveType,
			"status":          status,
			"matched_signers": aggregateChildMatchedSigners(children),
			"observed": map[string]any{
				"satisfied_children": satisfiedChildren,
				"total_children":     totalChildren,
			},
			"expected":     expected,
			"failure_code": failureValue,
			"children":     children,
		}, nil

	case "not":
		rawChild, ok := requirement["requirement"].(map[string]any)
		if !ok {
			return nil, errors.New("not child must be an object")
		}

		child, err := evaluateRequirementNode(
			rawChild,
			policySet,
			ctx,
			matchedSigners,
		)
		if err != nil {
			return nil, err
		}

		childSatisfied := resultSatisfied(child)
		satisfied := !childSatisfied
		status := "satisfied"
		var failureValue any
		if !satisfied {
			status = "unsatisfied"
			failureValue = "NOT_NOT_SATISFIED"
		}

		childStatus := "unsatisfied"
		if childSatisfied {
			childStatus = "satisfied"
		}

		requirementID, err := parser.AsString(
			requirement["requirement_id"],
			"requirement_id",
		)
		if err != nil {
			return nil, err
		}

		return map[string]any{
			"requirement_id":  requirementID,
			"type":            "not",
			"status":          status,
			"matched_signers": []string{},
			"observed": map[string]any{
				"child_status": childStatus,
			},
			"expected": map[string]any{
				"child_status": "unsatisfied",
			},
			"failure_code": failureValue,
			"children":     []any{child},
		}, nil

	case typePolicyRef:
		requirementID, err := parser.AsString(
			requirement["requirement_id"],
			"requirement_id",
		)
		if err != nil {
			return nil, err
		}
		policyID, err := parser.AsString(
			requirement["policy_id"],
			"policy_id",
		)
		if err != nil {
			return nil, err
		}
		version, err := parser.AsInt(
			requirement["policy_version"],
			"policy_version",
		)
		if err != nil {
			return nil, err
		}
		digest, err := parser.AsString(
			requirement["policy_digest"],
			"policy_digest",
		)
		if err != nil {
			return nil, err
		}
		referenced, ok := findPolicy(policySet, policyID, version)
		if !ok {
			return nil, fmt.Errorf(
				"referenced policy not found: %s/%d",
				policyID,
				version,
			)
		}

		nestedResults, nestedFailures, nestedStatus, err :=
			evaluateRequirementsWithSigners(
				referenced,
				policySet,
				ctx,
				matchedSigners,
			)
		if err != nil {
			return nil, err
		}

		referenceStatus := "satisfied"
		var referenceFailure any
		if nestedStatus != "satisfied" {
			referenceStatus = "unsatisfied"
			referenceFailure = "POLICY_REFERENCE_NOT_SATISFIED"
		}

		return map[string]any{
			"requirement_id":  requirementID,
			"type":            typePolicyRef,
			"status":          referenceStatus,
			"matched_signers": []string{},
			"observed": map[string]any{
				"policy_id":      policyID,
				"policy_version": version,
				"policy_digest":  digest,
				"policy_status":  nestedStatus,
			},
			"expected": map[string]any{
				"policy_status": "satisfied",
			},
			"failure_code": referenceFailure,
			"referenced_policy": map[string]any{
				"policy_id":           policyID,
				"policy_version":      version,
				"policy_digest":       digest,
				"status":              nestedStatus,
				"requirement_results": nestedResults,
				"failure_codes":       nestedFailures,
			},
		}, nil

	default:
		return nil, fmt.Errorf(
			"unsupported requirement type: %s",
			primitiveType,
		)
	}
}

func compareFailurePaths(left []string, right []string) int {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for index := 0; index < limit; index++ {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}

func projectRecursiveFailureCodes(results []any) []string {
	projected := []projectedFailure{}
	emissionIndex := 0

	var visit func(map[string]any, []string)
	visit = func(result map[string]any, pathPrefix []string) {
		if resultSatisfied(result) {
			return
		}

		requirementID, _ := result["requirement_id"].(string)
		failureCode, _ := result["failure_code"].(string)
		resultPath := append(
			append([]string(nil), pathPrefix...),
			requirementID,
		)
		projected = append(projected, projectedFailure{
			path:          resultPath,
			emissionIndex: emissionIndex,
			failureCode:   failureCode,
		})
		emissionIndex++

		primitiveType, _ := result["type"].(string)
		switch primitiveType {
		case "all_of":
			children, _ := result["children"].([]any)
			for _, rawChild := range children {
				child, ok := rawChild.(map[string]any)
				if ok && !resultSatisfied(child) {
					visit(child, pathPrefix)
				}
			}

		case "any_of":
			children, _ := result["children"].([]any)
			for _, rawChild := range children {
				child, ok := rawChild.(map[string]any)
				if ok {
					visit(child, pathPrefix)
				}
			}

		case "not":
			return

		case typePolicyRef:
			referenced, ok := result["referenced_policy"].(map[string]any)
			if !ok {
				return
			}
			nested, _ := referenced["requirement_results"].([]any)
			for _, rawNested := range nested {
				nestedResult, ok := rawNested.(map[string]any)
				if ok {
					visit(nestedResult, resultPath)
				}
			}
		}
	}

	for _, rawResult := range results {
		result, ok := rawResult.(map[string]any)
		if ok {
			visit(result, nil)
		}
	}

	sort.SliceStable(
		projected,
		func(left int, right int) bool {
			compared := compareFailurePaths(
				projected[left].path,
				projected[right].path,
			)
			if compared != 0 {
				return compared < 0
			}
			return projected[left].emissionIndex <
				projected[right].emissionIndex
		},
	)

	failures := make([]string, 0, len(projected))
	for _, item := range projected {
		failures = append(failures, item.failureCode)
	}
	return failures
}

// EvaluateRequirements evaluates a complete validated policy requirement tree
// without signer state. It remains for bounded compatibility callers.
func EvaluateRequirements(
	current model.Policy,
	policySet []model.Policy,
	ctx model.Context,
) ([]any, []string, string, error) {
	return evaluateRequirementsWithSigners(
		current,
		policySet,
		ctx,
		nil,
	)
}

func evaluateRequirementsWithSigners(
	current model.Policy,
	policySet []model.Policy,
	ctx model.Context,
	matchedSigners []string,
) ([]any, []string, string, error) {
	results := make([]any, 0, len(current.Requirements))
	satisfied := true

	for _, requirement := range current.Requirements {
		result, err := evaluateRequirementNode(
			requirement,
			policySet,
			ctx,
			matchedSigners,
		)
		if err != nil {
			return nil, nil, "", err
		}
		if !resultSatisfied(result) {
			satisfied = false
		}
		results = append(results, result)
	}

	status := "satisfied"
	if !satisfied {
		status = "unsatisfied"
	}

	return results, projectRecursiveFailureCodes(results), status, nil
}
