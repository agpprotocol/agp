package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
	"agpprotocol.org/agp/trust-primitive-engine/internal/validation"
)

const (
	typeIssuerIn              = "evidence_issuer_in"
	typeEvidenceIn            = "evidence_type_in"
	typeDistinctIssuer        = "evidence_distinct_issuers_at_least"
	typePolicyRef             = "policy_reference"
	maxPolicyReferenceDepth   = 8
	maxReferencedPolicies     = 32
	maxExpandedReferenceNodes = 2048
)

type policyBinding struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Digest  string `json:"digest"`
}

type participant struct {
	ID     string `json:"id"`
	Role   string `json:"role"`
	Weight int    `json:"weight"`
}

type evidence struct {
	ID           string `json:"id"`
	EvidenceType string `json:"evidence_type"`
	IssuerID     string `json:"issuer_id"`
}

type context struct {
	ObjectType   string        `json:"object_type"`
	ContextID    string        `json:"context_id"`
	Policy       policyBinding `json:"policy"`
	Participants []participant `json:"participants"`
	Evidence     []evidence    `json:"evidence"`
}

type signatureStatement struct {
	SignerID string `json:"signer_id"`
}

type signature struct {
	SignatureID string             `json:"signature_id"`
	Statement   signatureStatement `json:"statement"`
}

type evaluationInput struct {
	ObjectType    string      `json:"object_type"`
	ContextDigest string      `json:"context_digest"`
	Context       context     `json:"context"`
	Signatures    []signature `json:"signatures"`
}

type policy struct {
	ObjectType    string           `json:"object_type"`
	PolicyID      string           `json:"policy_id"`
	Version       int              `json:"version"`
	EligibleRoles []string         `json:"eligible_roles"`
	Requirements  []map[string]any `json:"requirements"`
}

func decodeFile(path string, target any) error {
	return parser.DecodeFile(path, target)
}

func asString(value any, field string) (string, error) {
	return parser.AsString(value, field)
}

func asInt(value any, field string) (int, error) {
	return parser.AsInt(value, field)
}

func asStrings(value any, field string) ([]string, error) {
	return parser.AsStrings(value, field)
}

func optionalStrings(requirement map[string]any, field string) ([]string, bool, error) {
	value, present := requirement[field]
	if !present {
		return nil, false, nil
	}
	result, err := asStrings(value, field)
	return result, true, err
}

func validateRequirement(requirement map[string]any) error {
	return validation.ValidateRequirement(requirement)
}

func validateRequirementTree(raw any) error {
	return validation.ValidateRequirementTree(raw)
}

func validatePolicy(value any) error {
	return validation.ValidatePolicy(value)
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
	ctx context,
	issuerIDs []string,
	filterIssuer bool,
	evidenceTypes []string,
	filterType bool,
) []evidence {
	unique := map[string]evidence{}
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

	result := make([]evidence, 0, len(ids))
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

func provenanceStatus(ctx context) string {
	if ctx.ObjectType == "agp.decision-context/3" {
		return "available"
	}
	return "unavailable"
}

func observedEntries(status string, entries []evidence) map[string]any {
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

func evaluateIssuerIn(requirement map[string]any, ctx context) (map[string]any, string, error) {
	requirementID, err := asString(requirement["requirement_id"], "requirement_id")
	if err != nil {
		return nil, "", err
	}
	issuerIDs, err := asStrings(requirement["issuer_ids"], "issuer_ids")
	if err != nil {
		return nil, "", err
	}
	evidenceTypes, hasTypes, err := optionalStrings(requirement, "evidence_types")
	if err != nil {
		return nil, "", err
	}

	status := provenanceStatus(ctx)
	entries := []evidence{}
	if status == "available" {
		entries = filteredEvidence(ctx, issuerIDs, true, evidenceTypes, hasTypes)
	}
	satisfied := status == "available" && len(entries) > 0
	failure := ""
	var failureValue any = nil
	resultStatus := "satisfied"
	if !satisfied {
		resultStatus = "unsatisfied"
		failure = "EVIDENCE_ISSUER_NOT_ALLOWED"
		failureValue = failure
	}

	var expectedTypes any = nil
	if hasTypes {
		expectedTypes = evidenceTypes
	}
	return map[string]any{
		"requirement_id":  requirementID,
		"type":            typeIssuerIn,
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

func evaluateEvidenceTypeIn(requirement map[string]any, ctx context) (map[string]any, string, error) {
	requirementID, err := asString(requirement["requirement_id"], "requirement_id")
	if err != nil {
		return nil, "", err
	}
	evidenceTypes, err := asStrings(requirement["evidence_types"], "evidence_types")
	if err != nil {
		return nil, "", err
	}
	issuerIDs, hasIssuers, err := optionalStrings(requirement, "issuer_ids")
	if err != nil {
		return nil, "", err
	}

	status := provenanceStatus(ctx)
	entries := []evidence{}
	if status == "available" {
		entries = filteredEvidence(ctx, issuerIDs, hasIssuers, evidenceTypes, true)
	}
	satisfied := status == "available" && len(entries) > 0
	failure := ""
	var failureValue any = nil
	resultStatus := "satisfied"
	if !satisfied {
		resultStatus = "unsatisfied"
		failure = "EVIDENCE_TYPE_NOT_ALLOWED"
		failureValue = failure
	}

	var expectedIssuers any = nil
	if hasIssuers {
		expectedIssuers = issuerIDs
	}
	return map[string]any{
		"requirement_id":  requirementID,
		"type":            typeEvidenceIn,
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

func evaluateDistinctIssuers(requirement map[string]any, ctx context) (map[string]any, string, error) {
	requirementID, err := asString(requirement["requirement_id"], "requirement_id")
	if err != nil {
		return nil, "", err
	}
	minimum, err := asInt(requirement["minimum"], "minimum")
	if err != nil {
		return nil, "", err
	}
	evidenceTypes, hasTypes, err := optionalStrings(requirement, "evidence_types")
	if err != nil {
		return nil, "", err
	}

	status := provenanceStatus(ctx)
	entries := []evidence{}
	if status == "available" {
		entries = filteredEvidence(ctx, nil, false, evidenceTypes, hasTypes)
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
	var failureValue any = nil
	resultStatus := "satisfied"
	if !satisfied {
		resultStatus = "unsatisfied"
		failure = "EVIDENCE_DISTINCT_ISSUER_MINIMUM_NOT_REACHED"
		failureValue = failure
	}

	var expectedTypes any = nil
	if hasTypes {
		expectedTypes = evidenceTypes
	}
	return map[string]any{
		"requirement_id":  requirementID,
		"type":            typeDistinctIssuer,
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

func findPolicy(policySet []policy, id string, version int) (policy, bool) {
	for _, candidate := range policySet {
		if candidate.PolicyID == id && candidate.Version == version {
			return candidate, true
		}
	}
	return policy{}, false
}

type graphValidationError struct {
	code   string
	detail string
}

func (err graphValidationError) Error() string {
	return err.detail
}

func graphError(code string, detail string) error {
	return graphValidationError{code: code, detail: detail}
}

func graphErrorCode(err error) string {
	var typed graphValidationError
	if errors.As(err, &typed) {
		return typed.code
	}
	return "INVALID_POLICY_REFERENCE_GRAPH"
}

func compactPolicyDigest(value policy) (string, error) {
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

func requirementNodes(requirements []map[string]any) ([]map[string]any, error) {
	nodes := []map[string]any{}

	var visit func(map[string]any) error
	visit = func(node map[string]any) error {
		nodes = append(nodes, node)

		primitiveType, err := asString(node["type"], "type")
		if err != nil {
			return err
		}

		switch primitiveType {
		case "all_of", "any_of":
			children, ok := node["requirements"].([]any)
			if !ok {
				return errors.New("composition requirements must be an array")
			}
			for _, rawChild := range children {
				child, ok := rawChild.(map[string]any)
				if !ok {
					return errors.New("composition child must be an object")
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

func policyIdentityKey(policyID string, version int, digest string) string {
	return fmt.Sprintf("%s\x00%d\x00%s", policyID, version, digest)
}

func validatePolicyReferenceGraphWithIdentityDigests(
	root policy,
	policySet []policy,
	declaredDigests map[string]string,
) error {
	index := map[string]policy{}
	digests := map[string]string{}

	for _, candidate := range policySet {
		key := fmt.Sprintf("%s\x00%d", candidate.PolicyID, candidate.Version)
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

	var visitPolicy func(policy, string, int) error
	visitPolicy = func(current policy, identity string, referenceDepth int) error {
		active[identity] = true
		defer delete(active, identity)

		nodes, err := requirementNodes(current.Requirements)
		if err != nil {
			return err
		}

		for _, requirement := range nodes {
			primitiveType, err := asString(requirement["type"], "type")
			if err != nil {
				return err
			}
			if primitiveType != typePolicyRef {
				continue
			}

			policyID, err := asString(requirement["policy_id"], "policy_id")
			if err != nil {
				return err
			}
			version, err := asInt(
				requirement["policy_version"],
				"policy_version",
			)
			if err != nil {
				return err
			}
			expectedDigest, err := asString(
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

func validatePolicyReferenceGraph(root policy, policySet []policy) error {
	return validatePolicyReferenceGraphWithIdentityDigests(
		root,
		policySet,
		nil,
	)
}

type policyGraphFixtureEntry struct {
	Policy         policy `json:"policy"`
	IdentityDigest string `json:"identity_digest"`
}

func policyGraphFixtureValidationReceipt(
	rootPath string,
	fixturePath string,
) error {
	var root policy
	var fixture []policyGraphFixtureEntry

	if err := decodeFile(rootPath, &root); err != nil {
		return err
	}
	if err := decodeFile(fixturePath, &fixture); err != nil {
		return err
	}

	policySet := make([]policy, 0, len(fixture))
	declaredDigests := map[string]string{}
	for _, entry := range fixture {
		policySet = append(policySet, entry.Policy)
		key := fmt.Sprintf(
			"%s\x00%d",
			entry.Policy.PolicyID,
			entry.Policy.Version,
		)
		declaredDigests[key] = entry.IdentityDigest
	}

	err := validatePolicyReferenceGraphWithIdentityDigests(
		root,
		policySet,
		declaredDigests,
	)
	receipt := map[string]any{
		"accepted":   err == nil,
		"error_code": nil,
	}
	if err != nil {
		receipt["error_code"] = graphErrorCode(err)
	}

	encoded, marshalErr := json.Marshal(receipt)
	if marshalErr != nil {
		return marshalErr
	}
	_, writeErr := os.Stdout.Write(encoded)
	return writeErr
}

func policyGraphValidationReceipt(rootPath string, policySetPath string) error {
	var root policy
	var policySet []policy

	if err := decodeFile(rootPath, &root); err != nil {
		return err
	}
	if err := decodeFile(policySetPath, &policySet); err != nil {
		return err
	}

	err := validatePolicyReferenceGraph(root, policySet)
	receipt := map[string]any{
		"accepted":   err == nil,
		"error_code": nil,
	}
	if err != nil {
		receipt["error_code"] = graphErrorCode(err)
	}

	encoded, marshalErr := json.Marshal(receipt)
	if marshalErr != nil {
		return marshalErr
	}
	_, writeErr := os.Stdout.Write(encoded)
	return writeErr
}

type projectedFailure struct {
	path          []string
	emissionIndex int
	failureCode   string
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
	policySet []policy,
	ctx context,
) (map[string]any, error) {
	primitiveType, err := asString(requirement["type"], "type")
	if err != nil {
		return nil, err
	}

	switch primitiveType {
	case typeIssuerIn:
		if err := validateRequirement(requirement); err != nil {
			return nil, err
		}
		result, _, err := evaluateIssuerIn(requirement, ctx)
		return result, err

	case typeEvidenceIn:
		if err := validateRequirement(requirement); err != nil {
			return nil, err
		}
		result, _, err := evaluateEvidenceTypeIn(requirement, ctx)
		return result, err

	case typeDistinctIssuer:
		if err := validateRequirement(requirement); err != nil {
			return nil, err
		}
		result, _, err := evaluateDistinctIssuers(requirement, ctx)
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
		var failureValue any = nil
		if !satisfied {
			status = "unsatisfied"
			failureValue = failureCode
		}

		requirementID, err := asString(
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
		)
		if err != nil {
			return nil, err
		}

		childSatisfied := resultSatisfied(child)
		satisfied := !childSatisfied
		status := "satisfied"
		var failureValue any = nil
		if !satisfied {
			status = "unsatisfied"
			failureValue = "NOT_NOT_SATISFIED"
		}

		childStatus := "unsatisfied"
		if childSatisfied {
			childStatus = "satisfied"
		}

		requirementID, err := asString(
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
		requirementID, innerErr := asString(
			requirement["requirement_id"],
			"requirement_id",
		)
		if innerErr != nil {
			return nil, innerErr
		}
		policyID, innerErr := asString(
			requirement["policy_id"],
			"policy_id",
		)
		if innerErr != nil {
			return nil, innerErr
		}
		version, innerErr := asInt(
			requirement["policy_version"],
			"policy_version",
		)
		if innerErr != nil {
			return nil, innerErr
		}
		digest, innerErr := asString(
			requirement["policy_digest"],
			"policy_digest",
		)
		if innerErr != nil {
			return nil, innerErr
		}
		referenced, ok := findPolicy(policySet, policyID, version)
		if !ok {
			return nil, fmt.Errorf(
				"referenced policy not found: %s/%d",
				policyID,
				version,
			)
		}

		nestedResults, nestedFailures, nestedStatus, innerErr :=
			evaluateRequirements(referenced, policySet, ctx)
		if innerErr != nil {
			return nil, innerErr
		}

		referenceStatus := "satisfied"
		var referenceFailure any = nil
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

func evaluateRequirements(
	current policy,
	policySet []policy,
	ctx context,
) ([]any, []string, string, error) {
	results := make([]any, 0, len(current.Requirements))
	satisfied := true

	for _, requirement := range current.Requirements {
		result, err := evaluateRequirementNode(
			requirement,
			policySet,
			ctx,
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

func signerProjection(
	input evaluationInput,
	root policy,
) (
	verifiedSignatureIDs []string,
	verifiedSigners []string,
	matchedSigners []string,
	unauthorized []string,
	ineligible []string,
	weight int,
) {
	verifiedSignatureIDs = []string{}
	verifiedSigners = []string{}
	matchedSigners = []string{}
	unauthorized = []string{}
	ineligible = []string{}
	signers := []string{}
	for _, item := range input.Signatures {
		verifiedSignatureIDs = append(
			verifiedSignatureIDs,
			item.SignatureID,
		)
		signers = append(signers, item.Statement.SignerID)
	}
	verifiedSignatureIDs = uniqueSorted(verifiedSignatureIDs)
	verifiedSigners = uniqueSorted(signers)

	participants := map[string]participant{}
	for _, item := range input.Context.Participants {
		participants[item.ID] = item
	}
	for _, signer := range verifiedSigners {
		item, ok := participants[signer]
		if !ok {
			unauthorized = append(unauthorized, signer)
			continue
		}
		if !contains(root.EligibleRoles, item.Role) {
			ineligible = append(ineligible, signer)
			continue
		}
		matchedSigners = append(matchedSigners, signer)
		weight += item.Weight
	}
	sort.Strings(matchedSigners)
	sort.Strings(unauthorized)
	sort.Strings(ineligible)
	return
}

func reproduce(
	input evaluationInput,
	root policy,
	policySet []policy,
) (map[string]any, error) {
	if err := validatePolicyReferenceGraph(root, policySet); err != nil {
		return nil, err
	}

	requirementResults, failureCodes, status, err :=
		evaluateRequirements(root, policySet, input.Context)
	if err != nil {
		return nil, err
	}

	verifiedSignatureIDs,
		verifiedSigners,
		matchedSigners,
		unauthorized,
		ineligible,
		weight := signerProjection(input, root)

	return map[string]any{
		"object_type":             "agp.trust-policy-evaluation/2",
		"status":                  status,
		"policy_id":               root.PolicyID,
		"policy_version":          root.Version,
		"policy_digest":           input.Context.Policy.Digest,
		"context_id":              input.Context.ContextID,
		"context_digest":          input.ContextDigest,
		"verified_signature_ids":  verifiedSignatureIDs,
		"verified_signers":        verifiedSigners,
		"matched_signers":         matchedSigners,
		"unauthorized_signers":    unauthorized,
		"ineligible_role_signers": ineligible,
		"signature_count":         len(verifiedSignatureIDs),
		"weight":                  weight,
		"requirement_results":     requirementResults,
		"failure_codes":           failureCodes,
	}, nil
}

func policyValidationReceipt(path string) error {
	var value any
	if err := decodeFile(path, &value); err != nil {
		return err
	}
	err := validatePolicy(value)
	receipt := map[string]any{
		"accepted":   err == nil,
		"error_code": nil,
	}
	if err != nil {
		receipt["error_code"] = "INVALID_POLICY"
	}
	encoded, marshalErr := json.Marshal(receipt)
	if marshalErr != nil {
		return marshalErr
	}
	_, writeErr := os.Stdout.Write(encoded)
	return writeErr
}

func validationReceipt(path string) error {
	var requirement map[string]any
	if err := decodeFile(path, &requirement); err != nil {
		return err
	}
	err := validateRequirement(requirement)
	receipt := map[string]any{
		"accepted":   err == nil,
		"error_code": nil,
	}
	if err != nil {
		receipt["error_code"] = "INVALID_REQUIREMENT"
	}
	encoded, marshalErr := json.Marshal(receipt)
	if marshalErr != nil {
		return marshalErr
	}
	_, writeErr := os.Stdout.Write(encoded)
	return writeErr
}

func main() {
	if len(os.Args) == 4 &&
		os.Args[1] == "--validate-policy-graph-fixture" {
		if err := policyGraphFixtureValidationReceipt(
			os.Args[2],
			os.Args[3],
		); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 4 && os.Args[1] == "--validate-policy-graph" {
		if err := policyGraphValidationReceipt(
			os.Args[2],
			os.Args[3],
		); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 3 && os.Args[1] == "--validate-policy" {
		if err := policyValidationReceipt(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 3 && os.Args[1] == "--validate-requirement" {
		if err := validationReceipt(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) != 4 {
		fmt.Fprintln(
			os.Stderr,
			"usage: agp-tpe26-reproduce evaluation-input.json root-policy.json policy-set.json",
		)
		os.Exit(2)
	}

	var input evaluationInput
	var root policy
	var policySet []policy

	if err := decodeFile(os.Args[1], &input); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := decodeFile(os.Args[2], &root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := decodeFile(os.Args[3], &policySet); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	result, err := reproduce(input, root, policySet)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
