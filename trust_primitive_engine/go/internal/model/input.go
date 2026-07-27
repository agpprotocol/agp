package model

// SignatureStatement identifies the signer asserted by one verified signature.
type SignatureStatement struct {
	SignerID string `json:"signer_id"`
}

// Signature is the bounded verified-signature representation used by the Go TPE.
type Signature struct {
	SignatureID string             `json:"signature_id"`
	Statement   SignatureStatement `json:"statement"`
}

// EvaluationInput is the bounded input representation consumed by the Go TPE.
type EvaluationInput struct {
	ObjectType    string      `json:"object_type"`
	ContextDigest string      `json:"context_digest"`
	Context       Context     `json:"context"`
	Signatures    []Signature `json:"signatures"`
}
