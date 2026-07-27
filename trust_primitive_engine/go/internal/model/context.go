package model

// PolicyBinding identifies the policy bound into a decision context.
type PolicyBinding struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Digest  string `json:"digest"`
}

// Proposal is the bounded proposal projection readable by context predicates.
type Proposal struct {
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
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
	Digest       string `json:"digest"`
	MediaType    string `json:"media_type"`
	EvidenceType string `json:"evidence_type"`
	IssuerID     string `json:"issuer_id"`
}

// Context is the bounded Decision Context representation used by the Go TPE.
type Context struct {
	ObjectType   string        `json:"object_type"`
	ContextID    string        `json:"context_id"`
	Policy       PolicyBinding `json:"policy"`
	Proposal     Proposal      `json:"proposal"`
	Participants []Participant `json:"participants"`
	Evidence     []Evidence    `json:"evidence"`
}
