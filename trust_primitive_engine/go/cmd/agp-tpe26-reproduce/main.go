package main

import (
	"encoding/json"
	"fmt"
	"os"

	"agpprotocol.org/agp/trust-primitive-engine/internal/engine"
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

type signatureStatement = model.SignatureStatement
type signature = model.Signature
type evaluationInput = model.EvaluationInput

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

func policyGraphValidationReceipt(
	rootPath string,
	policySetPath string,
) error {
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

func evaluateRequirements(
	current policy,
	policySet []policy,
	ctx context,
) ([]any, []string, string, error) {
	return engine.EvaluateRequirements(current, policySet, ctx)
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
	return engine.SignerProjection(input, root)
}

func reproduce(
	input evaluationInput,
	root policy,
	policySet []policy,
) (map[string]any, error) {
	return engine.Reproduce(input, root, policySet)
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
