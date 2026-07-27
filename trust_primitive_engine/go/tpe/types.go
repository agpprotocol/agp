package tpe

// Policy is the public Trust Policy 2 representation accepted by Evaluate.
// Requirement nodes retain their decoded JSON shape.
type Policy struct {
	ObjectType    string           `json:"object_type"`
	PolicyID      string           `json:"policy_id"`
	Version       int              `json:"version"`
	EligibleRoles []string         `json:"eligible_roles"`
	Requirements  []map[string]any `json:"requirements"`
}

// PolicyBinding identifies the policy bound into a decision context.
type PolicyBinding struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Digest  string `json:"digest"`
}

// Participant is one decision-context participant.
type Participant struct {
	ID     string `json:"id"`
	Role   string `json:"role"`
	Weight int    `json:"weight"`
}

// Evidence is one decision-context evidence manifest entry.
type Evidence struct {
	ID           string `json:"id"`
	EvidenceType string `json:"evidence_type"`
	IssuerID     string `json:"issuer_id"`
}

// Context is the bounded Decision Context representation accepted by Evaluate.
type Context struct {
	ObjectType   string        `json:"object_type"`
	ContextID    string        `json:"context_id"`
	Policy       PolicyBinding `json:"policy"`
	Participants []Participant `json:"participants"`
	Evidence     []Evidence    `json:"evidence"`
}

// SignatureStatement identifies the signer asserted by one verified signature.
type SignatureStatement struct {
	SignerID string `json:"signer_id"`
}

// Signature is the bounded verified-signature representation accepted by Evaluate.
type Signature struct {
	SignatureID string             `json:"signature_id"`
	Statement   SignatureStatement `json:"statement"`
}

// EvaluationInput is the complete bounded input accepted by Evaluate.
type EvaluationInput struct {
	ObjectType    string      `json:"object_type"`
	ContextDigest string      `json:"context_digest"`
	Context       Context     `json:"context"`
	Signatures    []Signature `json:"signatures"`
}

// Evaluation is the stable public Trust Policy Evaluation 2 result.
type Evaluation struct {
	ObjectType            string   `json:"object_type"`
	Status                string   `json:"status"`
	PolicyID              string   `json:"policy_id"`
	PolicyVersion         int      `json:"policy_version"`
	PolicyDigest          string   `json:"policy_digest"`
	ContextID             string   `json:"context_id"`
	ContextDigest         string   `json:"context_digest"`
	VerifiedSignatureIDs  []string `json:"verified_signature_ids"`
	VerifiedSigners       []string `json:"verified_signers"`
	MatchedSigners        []string `json:"matched_signers"`
	UnauthorizedSigners   []string `json:"unauthorized_signers"`
	IneligibleRoleSigners []string `json:"ineligible_role_signers"`
	SignatureCount        int      `json:"signature_count"`
	Weight                int      `json:"weight"`
	RequirementResults    []any    `json:"requirement_results"`
	FailureCodes          []string `json:"failure_codes"`
}
