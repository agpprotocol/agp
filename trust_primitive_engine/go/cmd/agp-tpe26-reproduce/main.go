package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
)

const (
	typeIssuerIn            = "evidence_issuer_in"
	typeEvidenceIn          = "evidence_type_in"
	typeDistinctIssuer      = "evidence_distinct_issuers_at_least"
	typePolicyRef           = "policy_reference"
	maxSetSize              = 64
	maxSafeInteger          = 9007199254740991
	maxRequirementDepth     = 8
	maxRequirementNodeCount = 256
)

var (
	identifierPattern = regexp.MustCompile(
		`^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$`,
	)
	evidenceTypePattern = regexp.MustCompile(
		`^[a-z0-9][a-z0-9._:/-]{1,123}[a-z0-9]/[1-9][0-9]*$`,
	)
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
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing JSON data")
	}
	return nil
}

func asString(value any, field string) (string, error) {
	result, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", field)
	}
	return result, nil
}

func asInt(value any, field string) (int, error) {
	switch typed := value.(type) {
	case json.Number:
		result, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", field)
		}
		return int(result), nil
	case float64:
		result := int(typed)
		if float64(result) != typed {
			return 0, fmt.Errorf("%s must be an integer", field)
		}
		return result, nil
	case int:
		return typed, nil
	default:
		return 0, fmt.Errorf("%s must be an integer", field)
	}
}

func asStrings(value any, field string) ([]string, error) {
	raw, ok := value.([]any)
	if !ok {
		if typed, ok := value.([]string); ok {
			return append([]string(nil), typed...), nil
		}
		return nil, fmt.Errorf("%s must be an array", field)
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain strings", field)
		}
		result = append(result, text)
	}
	return result, nil
}

func optionalStrings(requirement map[string]any, field string) ([]string, bool, error) {
	value, present := requirement[field]
	if !present {
		return nil, false, nil
	}
	result, err := asStrings(value, field)
	return result, true, err
}

func validateExactMembers(
	requirement map[string]any,
	required []string,
	optional []string,
) error {
	allowed := map[string]struct{}{}
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, present := requirement[key]; !present {
			return fmt.Errorf("missing member: %s", key)
		}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	for key := range requirement {
		if _, present := allowed[key]; !present {
			return fmt.Errorf("unknown member: %s", key)
		}
	}
	return nil
}

func validateIdentifier(value any, field string) (string, error) {
	text, err := asString(value, field)
	if err != nil {
		return "", err
	}
	if !identifierPattern.MatchString(text) {
		return "", fmt.Errorf("%s contains an invalid identifier", field)
	}
	return text, nil
}

func validateCanonicalSet(
	value any,
	field string,
	pattern *regexp.Regexp,
) ([]string, error) {
	values, err := asStrings(value, field)
	if err != nil {
		return nil, err
	}
	if len(values) < 1 || len(values) > maxSetSize {
		return nil, fmt.Errorf(
			"%s must contain between 1 and %d entries",
			field,
			maxSetSize,
		)
	}
	for _, item := range values {
		if !pattern.MatchString(item) {
			return nil, fmt.Errorf("%s contains an invalid value", field)
		}
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(values, sorted) {
		return nil, fmt.Errorf("%s must be in canonical order", field)
	}
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return nil, fmt.Errorf("%s must not contain duplicates", field)
		}
	}
	return values, nil
}

func validateRequirement(requirement map[string]any) error {
	primitiveType, err := asString(requirement["type"], "type")
	if err != nil {
		return err
	}

	switch primitiveType {
	case typeIssuerIn:
		if err := validateExactMembers(
			requirement,
			[]string{"requirement_id", "type", "issuer_ids"},
			[]string{"evidence_types"},
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["requirement_id"],
			"requirement_id",
		); err != nil {
			return err
		}
		if _, err := validateCanonicalSet(
			requirement["issuer_ids"],
			"issuer_ids",
			identifierPattern,
		); err != nil {
			return err
		}
		if value, present := requirement["evidence_types"]; present {
			if _, err := validateCanonicalSet(
				value,
				"evidence_types",
				evidenceTypePattern,
			); err != nil {
				return err
			}
		}
		return nil

	case typeEvidenceIn:
		if err := validateExactMembers(
			requirement,
			[]string{"requirement_id", "type", "evidence_types"},
			[]string{"issuer_ids"},
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["requirement_id"],
			"requirement_id",
		); err != nil {
			return err
		}
		if _, err := validateCanonicalSet(
			requirement["evidence_types"],
			"evidence_types",
			evidenceTypePattern,
		); err != nil {
			return err
		}
		if value, present := requirement["issuer_ids"]; present {
			if _, err := validateCanonicalSet(
				value,
				"issuer_ids",
				identifierPattern,
			); err != nil {
				return err
			}
		}
		return nil

	case typeDistinctIssuer:
		if err := validateExactMembers(
			requirement,
			[]string{"requirement_id", "type", "minimum"},
			[]string{"evidence_types"},
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["requirement_id"],
			"requirement_id",
		); err != nil {
			return err
		}
		minimum, err := asInt(requirement["minimum"], "minimum")
		if err != nil {
			return err
		}
		if minimum < 1 || minimum > 256 {
			return errors.New(
				"minimum must be an integer between 1 and 256",
			)
		}
		if value, present := requirement["evidence_types"]; present {
			if _, err := validateCanonicalSet(
				value,
				"evidence_types",
				evidenceTypePattern,
			); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported requirement type: %s", primitiveType)
	}
}

func validateRequirementTree(raw any) error {
	rawRequirements, ok := raw.([]any)
	if !ok || len(rawRequirements) == 0 {
		return errors.New("requirements must be a non-empty array")
	}

	seenIDs := map[string]struct{}{}
	nodeCount := 0

	var validateNode func(any, int) (string, error)
	validateNode = func(rawNode any, depth int) (string, error) {
		if depth > maxRequirementDepth {
			return "", fmt.Errorf(
				"requirement tree depth exceeds %d",
				maxRequirementDepth,
			)
		}

		nodeCount++
		if nodeCount > maxRequirementNodeCount {
			return "", fmt.Errorf(
				"requirement tree node count exceeds %d",
				maxRequirementNodeCount,
			)
		}

		node, ok := rawNode.(map[string]any)
		if !ok {
			return "", errors.New(
				"requirement tree node must be an object",
			)
		}

		requirementID, err := validateIdentifier(
			node["requirement_id"],
			"requirement_id",
		)
		if err != nil {
			return "", err
		}
		if _, exists := seenIDs[requirementID]; exists {
			return "", errors.New(
				"requirement_id values must be globally unique",
			)
		}
		seenIDs[requirementID] = struct{}{}

		operatorType, err := asString(node["type"], "type")
		if err != nil {
			return "", errors.New("primitive type must be a string")
		}

		switch operatorType {
		case "all_of", "any_of":
			if err := validateExactMembers(
				node,
				[]string{"requirement_id", "type", "requirements"},
				nil,
			); err != nil {
				return "", err
			}

			children, ok := node["requirements"].([]any)
			if !ok || len(children) < 2 {
				return "", fmt.Errorf(
					"%s requirements must contain at least two children",
					operatorType,
				)
			}

			childIDs := make([]string, 0, len(children))
			for _, child := range children {
				childID, err := validateNode(child, depth+1)
				if err != nil {
					return "", err
				}
				childIDs = append(childIDs, childID)
			}

			sortedIDs := append([]string(nil), childIDs...)
			sort.Strings(sortedIDs)
			if !reflect.DeepEqual(childIDs, sortedIDs) {
				return "", fmt.Errorf(
					"%s children must be ordered by requirement_id",
					operatorType,
				)
			}

		case "not":
			if err := validateExactMembers(
				node,
				[]string{"requirement_id", "type", "requirement"},
				nil,
			); err != nil {
				return "", err
			}
			if _, err := validateNode(node["requirement"], depth+1); err != nil {
				return "", err
			}

		default:
			if err := validateRequirement(node); err != nil {
				return "", err
			}
		}

		return requirementID, nil
	}

	topLevelIDs := make([]string, 0, len(rawRequirements))
	for _, rawRequirement := range rawRequirements {
		requirementID, err := validateNode(rawRequirement, 1)
		if err != nil {
			return err
		}
		topLevelIDs = append(topLevelIDs, requirementID)
	}

	sortedTopLevelIDs := append([]string(nil), topLevelIDs...)
	sort.Strings(sortedTopLevelIDs)
	if !reflect.DeepEqual(topLevelIDs, sortedTopLevelIDs) {
		return errors.New(
			"requirements must be ordered by requirement_id",
		)
	}

	return nil
}

func validatePolicy(value any) error {
	policyValue, ok := value.(map[string]any)
	if !ok {
		return errors.New("trust policy must be an object")
	}

	if err := validateExactMembers(
		policyValue,
		[]string{
			"object_type",
			"policy_id",
			"version",
			"eligible_roles",
			"requirements",
		},
		nil,
	); err != nil {
		return err
	}

	objectType, err := asString(policyValue["object_type"], "object_type")
	if err != nil {
		return err
	}
	if objectType != "agp.trust-policy/2" {
		return errors.New("object_type must be agp.trust-policy/2")
	}

	if _, err := validateIdentifier(
		policyValue["policy_id"],
		"policy_id",
	); err != nil {
		return err
	}

	version, err := asInt(policyValue["version"], "version")
	if err != nil {
		return err
	}
	if version < 1 || version > maxSafeInteger {
		return fmt.Errorf(
			"version must be an integer from 1 to %d",
			maxSafeInteger,
		)
	}

	roles, err := asStrings(policyValue["eligible_roles"], "eligible_roles")
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		return errors.New("eligible_roles must be a non-empty array")
	}
	allowedRoles := map[string]struct{}{
		"approver": {},
		"observer": {},
		"proposer": {},
		"reviewer": {},
		"voter":    {},
	}
	for _, role := range roles {
		if _, present := allowedRoles[role]; !present {
			return errors.New("eligible_roles contains an unsupported role")
		}
	}
	sortedRoles := append([]string(nil), roles...)
	sort.Strings(sortedRoles)
	if !reflect.DeepEqual(roles, sortedRoles) {
		return errors.New("eligible_roles must be lexicographically sorted")
	}
	for index := 1; index < len(roles); index++ {
		if roles[index] == roles[index-1] {
			return errors.New("eligible_roles must not contain duplicates")
		}
	}

	return validateRequirementTree(policyValue["requirements"])
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

func evaluateRequirements(
	current policy,
	policySet []policy,
	ctx context,
) ([]any, []string, string, error) {
	results := make([]any, 0, len(current.Requirements))
	failures := []string{}

	for _, requirement := range current.Requirements {
		primitiveType, err := asString(requirement["type"], "type")
		if err != nil {
			return nil, nil, "", err
		}
		if primitiveType != typePolicyRef {
			if err := validateRequirement(requirement); err != nil {
				return nil, nil, "", err
			}
		}

		var result map[string]any
		var failure string

		switch primitiveType {
		case typeIssuerIn:
			result, failure, err = evaluateIssuerIn(requirement, ctx)
		case typeEvidenceIn:
			result, failure, err = evaluateEvidenceTypeIn(requirement, ctx)
		case typeDistinctIssuer:
			result, failure, err = evaluateDistinctIssuers(requirement, ctx)
		case typePolicyRef:
			requirementID, innerErr := asString(
				requirement["requirement_id"],
				"requirement_id",
			)
			if innerErr != nil {
				return nil, nil, "", innerErr
			}
			policyID, innerErr := asString(requirement["policy_id"], "policy_id")
			if innerErr != nil {
				return nil, nil, "", innerErr
			}
			version, innerErr := asInt(
				requirement["policy_version"],
				"policy_version",
			)
			if innerErr != nil {
				return nil, nil, "", innerErr
			}
			digest, innerErr := asString(
				requirement["policy_digest"],
				"policy_digest",
			)
			if innerErr != nil {
				return nil, nil, "", innerErr
			}
			referenced, ok := findPolicy(policySet, policyID, version)
			if !ok {
				return nil, nil, "", fmt.Errorf(
					"referenced policy not found: %s/%d",
					policyID,
					version,
				)
			}

			nestedResults, nestedFailures, nestedStatus, innerErr :=
				evaluateRequirements(referenced, policySet, ctx)
			if innerErr != nil {
				return nil, nil, "", innerErr
			}

			referenceStatus := "satisfied"
			var referenceFailure any = nil
			if nestedStatus != "satisfied" {
				referenceStatus = "unsatisfied"
				failure = "POLICY_REFERENCE_NOT_SATISFIED"
				referenceFailure = failure
			}

			result = map[string]any{
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
			}
			if failure != "" {
				failures = append(failures, failure)
				failures = append(failures, nestedFailures...)
			}
			results = append(results, result)
			continue
		default:
			return nil, nil, "", fmt.Errorf(
				"unsupported requirement type: %s",
				primitiveType,
			)
		}
		if err != nil {
			return nil, nil, "", err
		}
		results = append(results, result)
		if failure != "" {
			failures = append(failures, failure)
		}
	}

	status := "satisfied"
	if len(failures) > 0 {
		status = "unsatisfied"
	}
	return results, failures, status, nil
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
