package tpe

import (
	"encoding/json"
	"fmt"

	verifyapi "agpprotocol.org/agp/signed-decision-context/verify"
)

func signedFailureCode(code string) Code {
	switch code {
	case "SIGNATURE_VERIFICATION_FAILED":
		return CodeSignatureVerificationFailed
	case "UNKNOWN_VERIFICATION_KEY", "AMBIGUOUS_VERIFICATION_KEY":
		return CodeUnknownKey
	case "UNSUPPORTED_SIGNATURE_ALGORITHM":
		return CodeUnsupportedAlgorithm
	case "INVALID_SIGNATURE_ENCODING", "INVALID_SIGNATURE_LENGTH",
		"INVALID_PUBLIC_KEY_ENCODING", "INVALID_PUBLIC_KEY_LENGTH":
		return CodeInvalidSignature
	default:
		return CodeInvalidSignedDecisionContext
	}
}

func wrapSignedFailure(err error) error {
	status, code, detail, ok := verifyapi.FailureDetails(err)
	if !ok {
		return WrapError(
			CodeInvalidSignedDecisionContext,
			"signed decision context verification failed",
			err,
		)
	}
	return WrapError(
		signedFailureCode(code),
		fmt.Sprintf("%s: %s", status, detail),
		err,
	)
}

func verifiedInput(
	result verifyapi.VerificationResult,
) (EvaluationInput, error) {
	encodedContext, err := json.Marshal(result.Context)
	if err != nil {
		return EvaluationInput{}, WrapError(
			CodeInvalidSignedDecisionContext,
			"encode verified decision context",
			err,
		)
	}

	var context Context
	if err := json.Unmarshal(encodedContext, &context); err != nil {
		return EvaluationInput{}, WrapError(
			CodeInvalidSignedDecisionContext,
			"decode verified decision context",
			err,
		)
	}

	digestObject, ok := result.ContextDigest.(map[string]any)
	if !ok {
		return EvaluationInput{}, NewError(
			CodeInvalidSignedDecisionContext,
			"verified context digest is not an object",
		)
	}
	digest, ok := digestObject["value"].(string)
	if !ok || digest == "" {
		return EvaluationInput{}, NewError(
			CodeInvalidSignedDecisionContext,
			"verified context digest value is missing",
		)
	}

	signatures := make([]Signature, len(result.VerifiedSignatures))
	for index, item := range result.VerifiedSignatures {
		signatures[index] = Signature{
			SignatureID: item.SignatureID,
			Statement: SignatureStatement{
				SignerID: item.SignerID,
			},
		}
	}

	return EvaluationInput{
		ObjectType:    result.ObjectType,
		ContextDigest: digest,
		Context:       context,
		Signatures:    signatures,
	}, nil
}

// EvaluateSigned parses and verifies a Signed Decision Context and evaluates
// the authenticated Decision Context against the supplied root policy and
// policy set.
func EvaluateSigned(
	signedContextJSON []byte,
	keyringJSON []byte,
	root Policy,
	policySet []Policy,
) (Evaluation, error) {
	value, err := verifyapi.ParseJSON(signedContextJSON)
	if err != nil {
		return Evaluation{}, wrapSignedFailure(err)
	}

	keyring, err := verifyapi.ParseKeyring(keyringJSON)
	if err != nil {
		return Evaluation{}, wrapSignedFailure(err)
	}

	verified, err := verifyapi.VerifyTyped(value, keyring)
	if err != nil {
		return Evaluation{}, wrapSignedFailure(err)
	}

	input, err := verifiedInput(verified)
	if err != nil {
		return Evaluation{}, err
	}
	return Evaluate(input, root, policySet)
}
