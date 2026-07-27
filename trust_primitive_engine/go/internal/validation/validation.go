package validation

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	typeIssuerIn            = "evidence_issuer_in"
	typeEvidenceIn          = "evidence_type_in"
	typeDistinctIssuer      = "evidence_distinct_issuers_at_least"
	typeRequiredSigner      = "required_signer"
	typeSignerThreshold     = "signer_threshold"
	typeProhibitedSigner    = "prohibited_signer"
	typeAnyOfSigners        = "any_of_signers"
	typeAllOfSigners        = "all_of_signers"
	typeExactlyOneSigners   = "exactly_one_of_signers"
	typeAtLeastNSigners     = "at_least_n_signers"
	typeAtMostNSigners      = "at_most_n_signers"
	typeExactlyNSigners     = "exactly_n_signers"
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
	text, err := parser.AsString(value, field)
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
	values, err := parser.AsStrings(value, field)
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

// ValidateRequirement validates one TPE 2.6 evidence-provenance requirement.
func ValidateRequirement(requirement map[string]any) error {
	primitiveType, err := parser.AsString(requirement["type"], "type")
	if err != nil {
		return err
	}

	switch primitiveType {
	case typeRequiredSigner:
		if err := validateExactMembers(
			requirement,
			[]string{"requirement_id", "type", "signer_id"},
			nil,
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["requirement_id"],
			"requirement_id",
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["signer_id"],
			"signer_id",
		); err != nil {
			return err
		}
		return nil

	case typeProhibitedSigner:
		if err := validateExactMembers(
			requirement,
			[]string{"requirement_id", "type", "signer_id"},
			nil,
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["requirement_id"],
			"requirement_id",
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["signer_id"],
			"signer_id",
		); err != nil {
			return err
		}
		return nil

	case typeSignerThreshold:
		if err := validateExactMembers(
			requirement,
			[]string{
				"requirement_id",
				"type",
				"signer_ids",
				"minimum_signatures",
			},
			nil,
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["requirement_id"],
			"requirement_id",
		); err != nil {
			return err
		}
		signerIDs, err := validateCanonicalSet(
			requirement["signer_ids"],
			"signer_ids",
			identifierPattern,
		)
		if err != nil {
			return err
		}
		minimum, err := parser.AsInt(
			requirement["minimum_signatures"],
			"minimum_signatures",
		)
		if err != nil {
			return err
		}
		if minimum < 1 {
			return errors.New(
				"minimum_signatures must be a positive integer",
			)
		}
		if minimum > len(signerIDs) {
			return errors.New(
				"minimum_signatures must not exceed signer_ids length",
			)
		}
		return nil

	case typeAnyOfSigners, typeAllOfSigners, typeExactlyOneSigners:
		if err := validateExactMembers(
			requirement,
			[]string{"requirement_id", "type", "signer_ids"},
			nil,
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["requirement_id"],
			"requirement_id",
		); err != nil {
			return err
		}
		signerIDs, err := validateCanonicalSet(
			requirement["signer_ids"],
			"signer_ids",
			identifierPattern,
		)
		if err != nil {
			return err
		}
		if len(signerIDs) < 2 {
			return errors.New("signer_ids must contain at least two entries")
		}
		return nil

	case typeAtLeastNSigners, typeAtMostNSigners, typeExactlyNSigners:
		limitField := ""
		switch primitiveType {
		case typeAtLeastNSigners:
			limitField = "minimum_matches"
		case typeAtMostNSigners:
			limitField = "maximum_matches"
		case typeExactlyNSigners:
			limitField = "exact_matches"
		}
		if err := validateExactMembers(
			requirement,
			[]string{
				"requirement_id",
				"type",
				"signer_ids",
				limitField,
			},
			nil,
		); err != nil {
			return err
		}
		if _, err := validateIdentifier(
			requirement["requirement_id"],
			"requirement_id",
		); err != nil {
			return err
		}
		signerIDs, err := validateCanonicalSet(
			requirement["signer_ids"],
			"signer_ids",
			identifierPattern,
		)
		if err != nil {
			return err
		}
		if len(signerIDs) < 2 {
			return errors.New(
				"signer_ids must contain at least two entries",
			)
		}
		limit, err := parser.AsInt(requirement[limitField], limitField)
		if err != nil {
			return err
		}
		switch primitiveType {
		case typeAtMostNSigners:
			if limit < 0 || limit >= len(signerIDs) {
				return errors.New(
					"maximum_matches must be between zero and signer_ids length minus one",
				)
			}
		default:
			if limit < 1 || limit > len(signerIDs) {
				return fmt.Errorf(
					"%s must be between one and signer_ids length",
					limitField,
				)
			}
		}
		return nil

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
		minimum, err := parser.AsInt(requirement["minimum"], "minimum")
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

// ValidateRequirementTree validates recursive composition structure.
func ValidateRequirementTree(raw any) error {
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

		operatorType, err := parser.AsString(node["type"], "type")
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
			if err := ValidateRequirement(node); err != nil {
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

// ValidatePolicy validates one Trust Policy 2 document.
func ValidatePolicy(value any) error {
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

	objectType, err := parser.AsString(policyValue["object_type"], "object_type")
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

	version, err := parser.AsInt(policyValue["version"], "version")
	if err != nil {
		return err
	}
	if version < 1 || version > maxSafeInteger {
		return fmt.Errorf(
			"version must be an integer from 1 to %d",
			maxSafeInteger,
		)
	}

	roles, err := parser.AsStrings(policyValue["eligible_roles"], "eligible_roles")
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

	return ValidateRequirementTree(policyValue["requirements"])
}
