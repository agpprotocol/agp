package engine

import (
	"sort"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/validation"
)

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

// SignerProjection deterministically projects verified, matched, unauthorized,
// and role-ineligible signer identities for one root policy evaluation.
func SignerProjection(
	input model.EvaluationInput,
	root model.Policy,
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

	participants := map[string]model.Participant{}
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

// Reproduce assembles the complete deterministic TPE 2 evaluation object.
func Reproduce(
	input model.EvaluationInput,
	root model.Policy,
	policySet []model.Policy,
) (map[string]any, error) {
	if err := validation.ValidatePolicyReferenceGraph(
		root,
		policySet,
	); err != nil {
		return nil, err
	}

	verifiedSignatureIDs,
		verifiedSigners,
		matchedSigners,
		unauthorized,
		ineligible,
		weight := SignerProjection(input, root)

	requirementResults, failureCodes, status, err :=
		evaluateRequirementsWithSigners(
			root,
			policySet,
			input.Context,
			matchedSigners,
		)
	if err != nil {
		return nil, err
	}

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
		"signature_count":         len(matchedSigners),
		"weight":                  weight,
		"requirement_results":     requirementResults,
		"failure_codes":           failureCodes,
	}, nil
}
