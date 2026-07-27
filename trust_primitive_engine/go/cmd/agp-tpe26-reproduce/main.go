package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
	"agpprotocol.org/agp/trust-primitive-engine/internal/primitives/provenance"
	"agpprotocol.org/agp/trust-primitive-engine/internal/validation"
)

const (
	typeIssuerIn       = "evidence_issuer_in"
	typeEvidenceIn     = "evidence_type_in"
	typeDistinctIssuer = "evidence_distinct_issuers_at_least"
	typePolicyRef      = "policy_reference"
)

type policyBinding = model.PolicyBinding
type participant = model.Participant
type evidence = model.Evidence
type context = model.Context

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

type policy = model.Policy

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

func evaluateIssuerIn(
	requirement map[string]any,
	ctx context,
) (map[string]any, string, error) {
	return provenance.EvaluateIssuerIn(requirement, ctx)
}

func evaluateEvidenceTypeIn(
	requirement map[string]any,
	ctx context,
) (map[string]any, string, error) {
	return provenance.EvaluateEvidenceTypeIn(requirement, ctx)
}

func evaluateDistinctIssuers(
	requirement map[string]any,
	ctx context,
) (map[string]any, string, error) {
	return provenance.EvaluateDistinctIssuers(requirement, ctx)
}

func findPolicy(policySet []policy, id string, version int) (policy, bool) {
	for _, candidate := range policySet {
		if candidate.PolicyID == id && candidate.Version == version {
			return candidate, true
		}
	}
	return policy{}, false
}

func graphErrorCode(err error) string {
	return validation.GraphErrorCode(err)
}

func validatePolicyReferenceGraphWithIdentityDigests(
	root policy,
	policySet []policy,
	declaredDigests map[string]string,
) error {
	return validation.ValidatePolicyReferenceGraphWithIdentityDigests(
		root,
		policySet,
		declaredDigests,
	)
}

func validatePolicyReferenceGraph(
	root policy,
	policySet []policy,
) error {
	return validation.ValidatePolicyReferenceGraph(root, policySet)
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
