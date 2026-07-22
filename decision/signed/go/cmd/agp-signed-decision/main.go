package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

var decisionErrorOrder = map[string]int{
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

var requiredEnvelopeFields = []string{
	"envelope_id",
	"object_type",
	"issuer",
	"key_id",
	"issued_at",
	"expires_at",
	"nonce",
	"payload",
	"signature",
}

type Key struct {
	KeyID      string  `json:"key_id"`
	Issuer     string  `json:"issuer"`
	Algorithm  string  `json:"algorithm"`
	PublicKey  string  `json:"public_key"`
	ValidFrom  string  `json:"valid_from"`
	ValidUntil string  `json:"valid_until"`
	RevokedAt  *string `json:"revoked_at"`
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
	AuthoritySetDigest string `json:"authority_set_digest"`
	AuthoritySetID     string `json:"authority_set_id"`
	ContextType        string `json:"context_type"`
	DecisionNonce      string `json:"decision_nonce"`
	ExecutionDomain    string `json:"execution_domain"`
	PolicyDigest       string `json:"policy_digest"`
	PolicyID           string `json:"policy_id"`
	PolicyVersion      string `json:"policy_version"`
	ProposalRoot       string `json:"proposal_root"`
	ValidFrom          string `json:"valid_from"`
	ValidUntil         string `json:"valid_until"`
}

type DecisionPayload struct {
	AuthoritySet    AuthoritySet    `json:"authority_set"`
	DecisionContext DecisionContext `json:"decision_context"`
	Policy          Policy          `json:"policy"`
	Proposal        map[string]any  `json:"proposal"`
}

type Vector struct {
	Envelope                map[string]any `json:"envelope"`
	ExpectedExecutionDomain string         `json:"expected_execution_domain"`
	Keyring                 []Key          `json:"keyring"`
	SeenNonces              []string       `json:"seen_nonces"`
	VerificationTime        string         `json:"verification_time"`
}

type DecisionReceipt struct {
	Accepted           bool     `json:"accepted"`
	AuthoritySetDigest *string  `json:"authority_set_digest"`
	DecisionRoot       *string  `json:"decision_root"`
	ErrorCodes         []string `json:"error_codes"`
	ExecutionDomain    *string  `json:"execution_domain"`
	PolicyDigest       *string  `json:"policy_digest"`
	ProposalRoot       *string  `json:"proposal_root"`
}

/*
Field order intentionally matches Python's sort_keys=True output.
Do not reorder without checking byte-identical receipts.
*/
type IntegratedReceipt struct {
	Accepted           bool     `json:"accepted"`
	AuthoritySetDigest *string  `json:"authority_set_digest"`
	DecisionRoot       *string  `json:"decision_root"`
	EnvelopeID         any      `json:"envelope_id"`
	ErrorCodes         []string `json:"error_codes"`
	ExecutionDomain    *string  `json:"execution_domain"`
	Issuer             any      `json:"issuer"`
	KeyID              any      `json:"key_id"`
	ObjectType         any      `json:"object_type"`
	PayloadDigest      string   `json:"payload_digest"`
	PolicyDigest       *string  `json:"policy_digest"`
	ProposalRoot       *string  `json:"proposal_root"`
	ReplayToken        string   `json:"replay_token"`
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

func stringValue(object map[string]any, key string) string {
	value, ok := object[key].(string)
	if !ok {
		return ""
	}

	return value
}

func interfaceValue(object map[string]any, key string) any {
	value, ok := object[key]
	if !ok {
		return nil
	}

	return value
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}

func findKey(vector Vector, envelope map[string]any) *Key {
	keyID := stringValue(envelope, "key_id")
	issuer := stringValue(envelope, "issuer")

	for index := range vector.Keyring {
		key := &vector.Keyring[index]

		if key.KeyID == keyID && key.Issuer == issuer {
			return key
		}
	}

	return nil
}

func signableEnvelope(envelope map[string]any) map[string]any {
	signable := map[string]any{}

	for key, value := range envelope {
		if key != "signature" {
			signable[key] = value
		}
	}

	return signable
}

func verifySignedLayer(vector Vector) []string {
	envelope := vector.Envelope

	if envelope == nil {
		return []string{"INVALID_ENVELOPE"}
	}

	missing := []string{}

	for _, field := range requiredEnvelopeFields {
		if _, exists := envelope[field]; !exists {
			missing = append(missing, field)
		}
	}

	sort.Strings(missing)

	if len(missing) > 0 {
		return []string{
			"MISSING_FIELDS:" + strings.Join(missing, ","),
		}
	}

	if vector.VerificationTime == "" {
		return []string{"INVALID_VERIFICATION_TIME"}
	}

	key := findKey(vector, envelope)

	if key == nil {
		return []string{"UNKNOWN_KEY"}
	}

	if key.Algorithm != "Ed25519" {
		return []string{"UNSUPPORTED_ALGORITHM"}
	}

	if key.RevokedAt != nil &&
		*key.RevokedAt <= vector.VerificationTime {
		return []string{"KEY_REVOKED"}
	}

	if key.ValidFrom != "" &&
		vector.VerificationTime < key.ValidFrom {
		return []string{"KEY_NOT_YET_VALID"}
	}

	if key.ValidUntil != "" &&
		vector.VerificationTime > key.ValidUntil {
		return []string{"KEY_EXPIRED"}
	}

	if vector.VerificationTime <
		stringValue(envelope, "issued_at") {
		return []string{"ENVELOPE_NOT_YET_VALID"}
	}

	if vector.VerificationTime >
		stringValue(envelope, "expires_at") {
		return []string{"ENVELOPE_EXPIRED"}
	}

	replayToken := stringValue(envelope, "issuer") +
		"|" +
		stringValue(envelope, "nonce")

	if contains(vector.SeenNonces, replayToken) {
		return []string{"REPLAY_DETECTED"}
	}

	publicKey, publicKeyErr := base64.StdEncoding.DecodeString(
		key.PublicKey,
	)

	signature, signatureErr := base64.StdEncoding.DecodeString(
		stringValue(envelope, "signature"),
	)

	if publicKeyErr != nil ||
		signatureErr != nil ||
		len(publicKey) != ed25519.PublicKeySize ||
		len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(
			ed25519.PublicKey(publicKey),
			canonicalBytes(signableEnvelope(envelope)),
			signature,
		) {
		return []string{"INVALID_SIGNATURE"}
	}

	return []string{}
}

func normalizeAuthoritySet(authority AuthoritySet) AuthoritySet {
	members := make([]Member, len(authority.Members))

	for index, member := range authority.Members {
		roles := append([]string{}, member.Roles...)
		sort.Strings(roles)

		weight := member.Weight
		if weight == 0 {
			weight = 1
		}

		members[index] = Member{
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
		"authority_set_digest": context.AuthoritySetDigest,
		"authority_set_id":     context.AuthoritySetID,
		"context_type":         context.ContextType,
		"decision_nonce":       context.DecisionNonce,
		"execution_domain":     context.ExecutionDomain,
		"policy_digest":        context.PolicyDigest,
		"policy_id":            context.PolicyID,
		"policy_version":       context.PolicyVersion,
		"proposal_root":        context.ProposalRoot,
		"valid_from":           context.ValidFrom,
		"valid_until":          context.ValidUntil,
	}
}

func parseTimestamp(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("timestamp must end in Z")
	}

	return time.Parse(time.RFC3339, value)
}

func invalidDecisionReceipt() DecisionReceipt {
	return DecisionReceipt{
		Accepted:           false,
		AuthoritySetDigest: nil,
		DecisionRoot:       nil,
		ErrorCodes:         []string{"INVALID_DECISION_CONTEXT"},
		ExecutionDomain:    nil,
		PolicyDigest:       nil,
		ProposalRoot:       nil,
	}
}

func verifyDecision(
	payload DecisionPayload,
	expectedExecutionDomain string,
	verificationTimeValue string,
) DecisionReceipt {
	validFrom, err := parseTimestamp(
		payload.DecisionContext.ValidFrom,
	)
	if err != nil {
		return invalidDecisionReceipt()
	}

	validUntil, err := parseTimestamp(
		payload.DecisionContext.ValidUntil,
	)
	if err != nil || !validUntil.After(validFrom) {
		return invalidDecisionReceipt()
	}

	verificationTime, err := parseTimestamp(
		verificationTimeValue,
	)
	if err != nil {
		return invalidDecisionReceipt()
	}

	if payload.Policy.PolicyID == "" ||
		payload.Policy.PolicyVersion == "" ||
		payload.AuthoritySet.AuthoritySetID == "" ||
		payload.DecisionContext.DecisionNonce == "" {
		return invalidDecisionReceipt()
	}

	normalizedAuthority := normalizeAuthoritySet(
		payload.AuthoritySet,
	)

	proposalRoot := digest(payload.Proposal)
	policyDigest := digest(payload.Policy)
	authorityDigest := digest(normalizedAuthority)
	decisionRoot := digest(
		contextMap(payload.DecisionContext),
	)

	errors := []string{}

	if payload.DecisionContext.AGPProfile != profile {
		errors = append(errors, "UNSUPPORTED_PROFILE")
	}

	if payload.DecisionContext.ContextType != contextType {
		errors = append(
			errors,
			"INVALID_DECISION_CONTEXT",
		)
	}

	if payload.DecisionContext.ProposalRoot != proposalRoot {
		errors = append(
			errors,
			"PROPOSAL_ROOT_MISMATCH",
		)
	}

	if payload.DecisionContext.PolicyVersion !=
		payload.Policy.PolicyVersion {
		errors = append(
			errors,
			"POLICY_VERSION_MISMATCH",
		)
	}

	if payload.DecisionContext.PolicyID !=
		payload.Policy.PolicyID {
		errors = append(
			errors,
			"POLICY_DIGEST_MISMATCH",
		)
	}

	if payload.DecisionContext.PolicyDigest != policyDigest {
		errors = append(
			errors,
			"POLICY_DIGEST_MISMATCH",
		)
	}

	if payload.DecisionContext.AuthoritySetID !=
		normalizedAuthority.AuthoritySetID ||
		payload.DecisionContext.AuthoritySetDigest !=
			authorityDigest {
		errors = append(
			errors,
			"AUTHORITY_SET_MISMATCH",
		)
	}

	if payload.DecisionContext.ExecutionDomain !=
		expectedExecutionDomain {
		errors = append(
			errors,
			"EXECUTION_DOMAIN_MISMATCH",
		)
	}

	if verificationTime.Before(validFrom) {
		errors = append(
			errors,
			"DECISION_NOT_YET_VALID",
		)
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
		return decisionErrorOrder[errors[i]] <
			decisionErrorOrder[errors[j]]
	})

	executionDomain :=
		payload.DecisionContext.ExecutionDomain

	return DecisionReceipt{
		Accepted:           len(errors) == 0,
		AuthoritySetDigest: &authorityDigest,
		DecisionRoot:       &decisionRoot,
		ErrorCodes:         errors,
		ExecutionDomain:    &executionDomain,
		PolicyDigest:       &policyDigest,
		ProposalRoot:       &proposalRoot,
	}
}

func nullDecisionFields(
	vector Vector,
	errorCodes []string,
) IntegratedReceipt {
	envelope := vector.Envelope
	payload := interfaceValue(envelope, "payload")

	return IntegratedReceipt{
		Accepted:           false,
		AuthoritySetDigest: nil,
		DecisionRoot:       nil,
		EnvelopeID: interfaceValue(
			envelope,
			"envelope_id",
		),
		ErrorCodes:      errorCodes,
		ExecutionDomain: nil,
		Issuer:          interfaceValue(envelope, "issuer"),
		KeyID:           interfaceValue(envelope, "key_id"),
		ObjectType:      interfaceValue(envelope, "object_type"),
		PayloadDigest:   digest(payload),
		PolicyDigest:    nil,
		ProposalRoot:    nil,
		ReplayToken: stringValue(envelope, "issuer") +
			"|" +
			stringValue(envelope, "nonce"),
	}
}

func verify(vector Vector) IntegratedReceipt {
	signedErrors := verifySignedLayer(vector)

	if len(signedErrors) > 0 {
		return nullDecisionFields(vector, signedErrors)
	}

	envelope := vector.Envelope

	if stringValue(envelope, "object_type") !=
		"decision_context" {
		return nullDecisionFields(
			vector,
			[]string{"WRONG_OBJECT_TYPE"},
		)
	}

	payloadValue, exists := envelope["payload"]
	if !exists {
		return nullDecisionFields(
			vector,
			[]string{"INVALID_DECISION_PAYLOAD"},
		)
	}

	payloadBytes, err := json.Marshal(payloadValue)
	if err != nil {
		return nullDecisionFields(
			vector,
			[]string{"INVALID_DECISION_PAYLOAD"},
		)
	}

	var payload DecisionPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nullDecisionFields(
			vector,
			[]string{"INVALID_DECISION_PAYLOAD"},
		)
	}

	decisionReceipt := verifyDecision(
		payload,
		vector.ExpectedExecutionDomain,
		vector.VerificationTime,
	)

	return IntegratedReceipt{
		Accepted: decisionReceipt.Accepted,
		AuthoritySetDigest: decisionReceipt.
			AuthoritySetDigest,
		DecisionRoot: decisionReceipt.DecisionRoot,
		EnvelopeID: interfaceValue(
			envelope,
			"envelope_id",
		),
		ErrorCodes: decisionReceipt.ErrorCodes,
		ExecutionDomain: decisionReceipt.
			ExecutionDomain,
		Issuer:     interfaceValue(envelope, "issuer"),
		KeyID:      interfaceValue(envelope, "key_id"),
		ObjectType: interfaceValue(envelope, "object_type"),
		PayloadDigest: digest(
			interfaceValue(envelope, "payload"),
		),
		PolicyDigest: decisionReceipt.PolicyDigest,
		ProposalRoot: decisionReceipt.ProposalRoot,
		ReplayToken: stringValue(envelope, "issuer") +
			"|" +
			stringValue(envelope, "nonce"),
	}
}

func invalidInputReceipt() IntegratedReceipt {
	return IntegratedReceipt{
		Accepted:           false,
		AuthoritySetDigest: nil,
		DecisionRoot:       nil,
		EnvelopeID:         nil,
		ErrorCodes:         []string{"INVALID_INPUT"},
		ExecutionDomain:    nil,
		Issuer:             nil,
		KeyID:              nil,
		ObjectType:         nil,
		PayloadDigest:      digest(nil),
		PolicyDigest:       nil,
		ProposalRoot:       nil,
		ReplayToken:        "|",
	}
}

func writeReceipt(
	outputPath string,
	receipt IntegratedReceipt,
) {
	raw, err := json.Marshal(receipt)
	if err != nil {
		panic(err)
	}

	raw = append(raw, '\n')

	if err := os.MkdirAll(
		filepath.Dir(outputPath),
		0755,
	); err != nil {
		panic(err)
	}

	if err := os.WriteFile(
		outputPath,
		raw,
		0644,
	); err != nil {
		panic(err)
	}
}

func processFile(inputPath, outputPath string) {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		writeReceipt(outputPath, invalidInputReceipt())
		return
	}

	var vector Vector
	if err := json.Unmarshal(raw, &vector); err != nil {
		writeReceipt(outputPath, invalidInputReceipt())
		return
	}

	writeReceipt(outputPath, verify(vector))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(
			os.Stderr,
			"usage: agp-signed-decision "+
				"INPUT.json|INPUT_DIR "+
				"OUTPUT.json|OUTPUT_DIR",
		)
		os.Exit(2)
	}

	info, err := os.Stat(os.Args[1])
	if err != nil {
		panic(err)
	}

	if info.IsDir() {
		if err := os.MkdirAll(
			os.Args[2],
			0755,
		); err != nil {
			panic(err)
		}

		entries, err := os.ReadDir(os.Args[1])
		if err != nil {
			panic(err)
		}

		for _, entry := range entries {
			if entry.IsDir() ||
				filepath.Ext(entry.Name()) != ".json" {
				continue
			}

			processFile(
				filepath.Join(
					os.Args[1],
					entry.Name(),
				),
				filepath.Join(
					os.Args[2],
					entry.Name(),
				),
			)
		}

		return
	}

	processFile(os.Args[1], os.Args[2])
}
