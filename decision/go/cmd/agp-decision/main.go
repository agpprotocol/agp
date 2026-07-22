package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	profile     = "AGP-0.6"
	contextType = "agp-decision-context"
)

var errorOrder = map[string]int{
	"INVALID_DECISION_CONTEXT":  0,
	"UNSUPPORTED_PROFILE":       1,
	"PROPOSAL_ROOT_MISMATCH":    2,
	"POLICY_VERSION_MISMATCH":   3,
	"POLICY_DIGEST_MISMATCH":    4,
	"AUTHORITY_SET_MISMATCH":    5,
	"EXECUTION_DOMAIN_MISMATCH": 6,
	"DECISION_NOT_YET_VALID":    7,
	"DECISION_EXPIRED":          8,
}

type Member struct {
	MemberID string   `json:"member_id"`
	Roles    []string `json:"roles"`
	Weight   int      `json:"weight"`
}

type AuthoritySet struct {
	AuthoritySetID string   `json:"authority_set_id"`
	Members        []Member `json:"members"`
}

type Policy struct {
	PolicyID      string         `json:"policy_id"`
	PolicyVersion string         `json:"policy_version"`
	Rule          map[string]any `json:"rule"`
}

type DecisionContext struct {
	AGPProfile         string `json:"agp_profile"`
	ContextType        string `json:"context_type"`
	ProposalRoot       string `json:"proposal_root"`
	PolicyID           string `json:"policy_id"`
	PolicyVersion      string `json:"policy_version"`
	PolicyDigest       string `json:"policy_digest"`
	AuthoritySetID     string `json:"authority_set_id"`
	AuthoritySetDigest string `json:"authority_set_digest"`
	ExecutionDomain    string `json:"execution_domain"`
	ValidFrom          string `json:"valid_from"`
	ValidUntil         string `json:"valid_until"`
	DecisionNonce      string `json:"decision_nonce"`
}

type Input struct {
	Proposal                map[string]any  `json:"proposal"`
	Policy                  Policy          `json:"policy"`
	AuthoritySet            AuthoritySet    `json:"authority_set"`
	ExpectedExecutionDomain string          `json:"expected_execution_domain"`
	VerificationTime        string          `json:"verification_time"`
	DecisionContext         DecisionContext `json:"decision_context"`
}

type Receipt struct {
	Accepted           bool     `json:"accepted"`
	AuthoritySetDigest *string  `json:"authority_set_digest"`
	DecisionRoot       *string  `json:"decision_root"`
	ErrorCodes         []string `json:"error_codes"`
	ExecutionDomain    *string  `json:"execution_domain"`
	PolicyDigest       *string  `json:"policy_digest"`
	ProposalRoot       *string  `json:"proposal_root"`
}

func canonicalBytes(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	var canonical any
	if err := json.Unmarshal(raw, &canonical); err != nil {
		panic(err)
	}

	encoded, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}

	return encoded
}

func digest(value any) string {
	sum := sha256.Sum256(canonicalBytes(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizeAuthoritySet(authority AuthoritySet) AuthoritySet {
	members := make([]Member, len(authority.Members))

	for i, member := range authority.Members {
		roles := append([]string{}, member.Roles...)
		sort.Strings(roles)

		weight := member.Weight
		if weight == 0 {
			weight = 1
		}

		members[i] = Member{
			MemberID: member.MemberID,
			Roles:    roles,
			Weight:   weight,
		}
	}

	sort.Slice(members, func(i, j int) bool {
		return members[i].MemberID < members[j].MemberID
	})

	return AuthoritySet{
		AuthoritySetID: authority.AuthoritySetID,
		Members:        members,
	}
}

func contextMap(context DecisionContext) map[string]any {
	return map[string]any{
		"agp_profile":          context.AGPProfile,
		"context_type":         context.ContextType,
		"proposal_root":        context.ProposalRoot,
		"policy_id":            context.PolicyID,
		"policy_version":       context.PolicyVersion,
		"policy_digest":        context.PolicyDigest,
		"authority_set_id":     context.AuthoritySetID,
		"authority_set_digest": context.AuthoritySetDigest,
		"execution_domain":     context.ExecutionDomain,
		"valid_from":           context.ValidFrom,
		"valid_until":          context.ValidUntil,
		"decision_nonce":       context.DecisionNonce,
	}
}

func parseTimestamp(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("timestamp must end in Z")
	}

	return time.Parse(time.RFC3339, value)
}

func invalidReceipt() Receipt {
	return Receipt{
		Accepted:           false,
		AuthoritySetDigest: nil,
		DecisionRoot:       nil,
		ErrorCodes:         []string{"INVALID_DECISION_CONTEXT"},
		ExecutionDomain:    nil,
		PolicyDigest:       nil,
		ProposalRoot:       nil,
	}
}

func verify(input Input) Receipt {
	validFrom, err := parseTimestamp(input.DecisionContext.ValidFrom)
	if err != nil {
		return invalidReceipt()
	}

	validUntil, err := parseTimestamp(input.DecisionContext.ValidUntil)
	if err != nil || !validUntil.After(validFrom) {
		return invalidReceipt()
	}

	verificationTime, err := parseTimestamp(input.VerificationTime)
	if err != nil {
		return invalidReceipt()
	}

	if input.Policy.PolicyID == "" ||
		input.Policy.PolicyVersion == "" ||
		input.AuthoritySet.AuthoritySetID == "" ||
		input.DecisionContext.DecisionNonce == "" {
		return invalidReceipt()
	}

	normalizedAuthority := normalizeAuthoritySet(input.AuthoritySet)

	proposalRoot := digest(input.Proposal)
	policyDigest := digest(input.Policy)
	authorityDigest := digest(normalizedAuthority)
	decisionRoot := digest(contextMap(input.DecisionContext))

	errors := []string{}

	if input.DecisionContext.AGPProfile != profile {
		errors = append(errors, "UNSUPPORTED_PROFILE")
	}

	if input.DecisionContext.ContextType != contextType {
		errors = append(errors, "INVALID_DECISION_CONTEXT")
	}

	if input.DecisionContext.ProposalRoot != proposalRoot {
		errors = append(errors, "PROPOSAL_ROOT_MISMATCH")
	}

	if input.DecisionContext.PolicyVersion != input.Policy.PolicyVersion {
		errors = append(errors, "POLICY_VERSION_MISMATCH")
	}

	if input.DecisionContext.PolicyID != input.Policy.PolicyID {
		errors = append(errors, "POLICY_DIGEST_MISMATCH")
	}

	if input.DecisionContext.PolicyDigest != policyDigest {
		errors = append(errors, "POLICY_DIGEST_MISMATCH")
	}

	if input.DecisionContext.AuthoritySetID != normalizedAuthority.AuthoritySetID ||
		input.DecisionContext.AuthoritySetDigest != authorityDigest {
		errors = append(errors, "AUTHORITY_SET_MISMATCH")
	}

	if input.DecisionContext.ExecutionDomain != input.ExpectedExecutionDomain {
		errors = append(errors, "EXECUTION_DOMAIN_MISMATCH")
	}

	if verificationTime.Before(validFrom) {
		errors = append(errors, "DECISION_NOT_YET_VALID")
	}

	if !verificationTime.Before(validUntil) {
		errors = append(errors, "DECISION_EXPIRED")
	}

	unique := map[string]bool{}
	for _, code := range errors {
		unique[code] = true
	}

	errors = errors[:0]
	for code := range unique {
		errors = append(errors, code)
	}

	sort.Slice(errors, func(i, j int) bool {
		return errorOrder[errors[i]] < errorOrder[errors[j]]
	})

	executionDomain := input.DecisionContext.ExecutionDomain

	return Receipt{
		Accepted:           len(errors) == 0,
		AuthoritySetDigest: &authorityDigest,
		DecisionRoot:       &decisionRoot,
		ErrorCodes:         errors,
		ExecutionDomain:    &executionDomain,
		PolicyDigest:       &policyDigest,
		ProposalRoot:       &proposalRoot,
	}
}

func processFile(inputPath, outputPath string) {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		panic(err)
	}

	var input Input
	if err := json.Unmarshal(raw, &input); err != nil {
		receipt := invalidReceipt()
		writeReceipt(outputPath, receipt)
		return
	}

	writeReceipt(outputPath, verify(input))
}

func writeReceipt(outputPath string, receipt Receipt) {
	raw, err := json.Marshal(receipt)
	if err != nil {
		panic(err)
	}

	raw = append(raw, '\n')

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		panic(err)
	}

	if err := os.WriteFile(outputPath, raw, 0644); err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(
			os.Stderr,
			"usage: agp-decision INPUT.json|INPUT_DIR OUTPUT.json|OUTPUT_DIR",
		)
		os.Exit(2)
	}

	info, err := os.Stat(os.Args[1])
	if err != nil {
		panic(err)
	}

	if info.IsDir() {
		if err := os.MkdirAll(os.Args[2], 0755); err != nil {
			panic(err)
		}

		entries, err := os.ReadDir(os.Args[1])
		if err != nil {
			panic(err)
		}

		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}

			processFile(
				filepath.Join(os.Args[1], entry.Name()),
				filepath.Join(os.Args[2], entry.Name()),
			)
		}

		return
	}

	processFile(os.Args[1], os.Args[2])
}
