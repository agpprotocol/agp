package tpe

import (
	"encoding/json"

	"agpprotocol.org/agp/trust-primitive-engine/internal/engine"
	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func toInternalPolicy(value Policy) model.Policy {
	return model.Policy{
		ObjectType:    value.ObjectType,
		PolicyID:      value.PolicyID,
		Version:       value.Version,
		EligibleRoles: append([]string(nil), value.EligibleRoles...),
		Requirements:  append([]map[string]any(nil), value.Requirements...),
	}
}

func toInternalContext(value Context) model.Context {
	participants := make([]model.Participant, len(value.Participants))
	for index, item := range value.Participants {
		participants[index] = model.Participant{
			ID:     item.ID,
			Role:   item.Role,
			Weight: item.Weight,
		}
	}

	evidence := make([]model.Evidence, len(value.Evidence))
	for index, item := range value.Evidence {
		evidence[index] = model.Evidence{
			ID:           item.ID,
			EvidenceType: item.EvidenceType,
			IssuerID:     item.IssuerID,
		}
	}

	return model.Context{
		ObjectType: value.ObjectType,
		ContextID:  value.ContextID,
		Policy: model.PolicyBinding{
			ID:      value.Policy.ID,
			Version: value.Policy.Version,
			Digest:  value.Policy.Digest,
		},
		Participants: participants,
		Evidence:     evidence,
	}
}

func toInternalInput(value EvaluationInput) model.EvaluationInput {
	signatures := make([]model.Signature, len(value.Signatures))
	for index, item := range value.Signatures {
		signatures[index] = model.Signature{
			SignatureID: item.SignatureID,
			Statement: model.SignatureStatement{
				SignerID: item.Statement.SignerID,
			},
		}
	}

	return model.EvaluationInput{
		ObjectType:    value.ObjectType,
		ContextDigest: value.ContextDigest,
		Context:       toInternalContext(value.Context),
		Signatures:    signatures,
	}
}

// Evaluate deterministically evaluates one root policy and its policy set.
//
// Evaluation-level unsatisfaction is returned as a successful Evaluation with
// Status equal to "unsatisfied". The error return is reserved for fatal input,
// validation, reference, or execution failures.
func Evaluate(
	input EvaluationInput,
	root Policy,
	policySet []Policy,
) (Evaluation, error) {
	internalPolicySet := make([]model.Policy, len(policySet))
	for index, item := range policySet {
		internalPolicySet[index] = toInternalPolicy(item)
	}

	raw, err := engine.Reproduce(
		toInternalInput(input),
		toInternalPolicy(root),
		internalPolicySet,
	)
	if err != nil {
		return Evaluation{}, err
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return Evaluation{}, WrapError(
			CodeInvalidJSON,
			"encode evaluation result",
			err,
		)
	}

	var result Evaluation
	if err := json.Unmarshal(encoded, &result); err != nil {
		return Evaluation{}, WrapError(
			CodeInvalidJSON,
			"decode evaluation result",
			err,
		)
	}
	return result, nil
}
