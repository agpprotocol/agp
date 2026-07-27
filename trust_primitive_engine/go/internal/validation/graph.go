package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	typePolicyRef             = "policy_reference"
	maxPolicyReferenceDepth   = 8
	maxReferencedPolicies     = 32
	maxExpandedReferenceNodes = 2048
)

// GraphError reports a normative policy-reference graph failure.
type GraphError struct {
	Code   string
	Detail string
}

func (err GraphError) Error() string {
	return err.Detail
}

func graphError(code string, detail string) error {
	return GraphError{Code: code, Detail: detail}
}

// GraphErrorCode returns the normative graph error code or the generic
// fallback used by the bounded reproducer.
func GraphErrorCode(err error) string {
	var typed GraphError
	if errors.As(err, &typed) {
		return typed.Code
	}
	return "INVALID_POLICY_REFERENCE_GRAPH"
}

func compactPolicyDigest(value model.Policy) (string, error) {
	canonicalValue := map[string]any{
		"eligible_roles": value.EligibleRoles,
		"object_type":    value.ObjectType,
		"policy_id":      value.PolicyID,
		"requirements":   value.Requirements,
		"version":        value.Version,
	}

	encoded, err := json.Marshal(canonicalValue)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func requirementNodes(
	requirements []map[string]any,
) ([]map[string]any, error) {
	nodes := []map[string]any{}

	var visit func(map[string]any) error
	visit = func(node map[string]any) error {
		nodes = append(nodes, node)

		primitiveType, err := parser.AsString(node["type"], "type")
		if err != nil {
			return err
		}

		switch primitiveType {
		case "all_of", "any_of":
			children, ok := node["requirements"].([]any)
			if !ok {
				return errors.New(
					"composition requirements must be an array",
				)
			}
			for _, rawChild := range children {
				child, ok := rawChild.(map[string]any)
				if !ok {
					return errors.New(
						"composition child must be an object",
					)
				}
				if err := visit(child); err != nil {
					return err
				}
			}
		case "not":
			child, ok := node["requirement"].(map[string]any)
			if !ok {
				return errors.New("not child must be an object")
			}
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}

	for _, requirement := range requirements {
		if err := visit(requirement); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func policyIdentityKey(
	policyID string,
	version int,
	digest string,
) string {
	return fmt.Sprintf("%s\x00%d\x00%s", policyID, version, digest)
}

// ValidatePolicyReferenceGraphWithIdentityDigests validates the complete
// reachable graph. declaredDigests is reserved for controlled conformance
// fixtures that need otherwise-impossible cycle identities.
func ValidatePolicyReferenceGraphWithIdentityDigests(
	root model.Policy,
	policySet []model.Policy,
	declaredDigests map[string]string,
) error {
	index := map[string]model.Policy{}
	digests := map[string]string{}

	for _, candidate := range policySet {
		key := fmt.Sprintf(
			"%s\x00%d",
			candidate.PolicyID,
			candidate.Version,
		)
		if _, exists := index[key]; exists {
			return graphError(
				"INVALID_TRUST_POLICY_SET",
				"duplicate policy_id/version",
			)
		}

		digest, declared := declaredDigests[key]
		if !declared {
			var err error
			digest, err = compactPolicyDigest(candidate)
			if err != nil {
				return err
			}
		}
		index[key] = candidate
		digests[key] = digest
	}

	rootDigest, err := compactPolicyDigest(root)
	if err != nil {
		return err
	}

	rootNodes, err := requirementNodes(root.Requirements)
	if err != nil {
		return err
	}
	expandedNodeCount := len(rootNodes)
	if expandedNodeCount > maxExpandedReferenceNodes {
		return graphError(
			"POLICY_REFERENCE_NODE_LIMIT_EXCEEDED",
			fmt.Sprintf(
				"expanded_requirement_count=%d limit=%d",
				expandedNodeCount,
				maxExpandedReferenceNodes,
			),
		)
	}

	active := map[string]bool{}
	completed := map[string]bool{}
	reachable := map[string]bool{}

	var visitPolicy func(model.Policy, string, int) error
	visitPolicy = func(
		current model.Policy,
		identity string,
		referenceDepth int,
	) error {
		active[identity] = true
		defer delete(active, identity)

		nodes, err := requirementNodes(current.Requirements)
		if err != nil {
			return err
		}

		for _, requirement := range nodes {
			primitiveType, err := parser.AsString(
				requirement["type"],
				"type",
			)
			if err != nil {
				return err
			}
			if primitiveType != typePolicyRef {
				continue
			}

			policyID, err := parser.AsString(
				requirement["policy_id"],
				"policy_id",
			)
			if err != nil {
				return err
			}
			version, err := parser.AsInt(
				requirement["policy_version"],
				"policy_version",
			)
			if err != nil {
				return err
			}
			expectedDigest, err := parser.AsString(
				requirement["policy_digest"],
				"policy_digest",
			)
			if err != nil {
				return err
			}

			lookupKey := fmt.Sprintf("%s\x00%d", policyID, version)
			referenced, exists := index[lookupKey]
			if !exists {
				return graphError(
					"POLICY_REFERENCE_NOT_FOUND",
					fmt.Sprintf(
						"policy_id=%s policy_version=%d",
						policyID,
						version,
					),
				)
			}

			computedDigest := digests[lookupKey]
			if computedDigest != expectedDigest {
				return graphError(
					"POLICY_REFERENCE_DIGEST_MISMATCH",
					fmt.Sprintf(
						"reference=%s computed=%s",
						expectedDigest,
						computedDigest,
					),
				)
			}

			referencedIdentity := policyIdentityKey(
				policyID,
				version,
				computedDigest,
			)
			if active[referencedIdentity] {
				return graphError(
					"POLICY_REFERENCE_CYCLE",
					fmt.Sprintf(
						"policy_id=%s policy_version=%d",
						policyID,
						version,
					),
				)
			}
			if completed[referencedIdentity] {
				continue
			}

			nextDepth := referenceDepth + 1
			if nextDepth > maxPolicyReferenceDepth {
				return graphError(
					"POLICY_REFERENCE_DEPTH_EXCEEDED",
					fmt.Sprintf(
						"reference_depth=%d limit=%d",
						nextDepth,
						maxPolicyReferenceDepth,
					),
				)
			}

			if !reachable[referencedIdentity] {
				if len(reachable)+1 > maxReferencedPolicies {
					return graphError(
						"POLICY_REFERENCE_COUNT_EXCEEDED",
						fmt.Sprintf(
							"referenced_policy_count=%d limit=%d",
							len(reachable)+1,
							maxReferencedPolicies,
						),
					)
				}

				referencedNodes, err := requirementNodes(
					referenced.Requirements,
				)
				if err != nil {
					return err
				}
				expandedNodeCount += len(referencedNodes)
				if expandedNodeCount > maxExpandedReferenceNodes {
					return graphError(
						"POLICY_REFERENCE_NODE_LIMIT_EXCEEDED",
						fmt.Sprintf(
							"expanded_requirement_count=%d limit=%d",
							expandedNodeCount,
							maxExpandedReferenceNodes,
						),
					)
				}
				reachable[referencedIdentity] = true
			}

			if err := visitPolicy(
				referenced,
				referencedIdentity,
				nextDepth,
			); err != nil {
				return err
			}
		}

		completed[identity] = true
		return nil
	}

	return visitPolicy(
		root,
		policyIdentityKey(root.PolicyID, root.Version, rootDigest),
		0,
	)
}

// ValidatePolicyReferenceGraph validates the production graph using computed
// canonical policy digests.
func ValidatePolicyReferenceGraph(
	root model.Policy,
	policySet []model.Policy,
) error {
	return ValidatePolicyReferenceGraphWithIdentityDigests(
		root,
		policySet,
		nil,
	)
}
