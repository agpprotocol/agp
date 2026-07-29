package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"agpprotocol.org/agp/signed-decision-context/internal/canonicaljson"
	verifyapi "agpprotocol.org/agp/signed-decision-context/verify"
)

const supportedAlgorithm = "ed25519"

// Code is a stable signing failure code.
type Code string

const (
	CodeInvalidPrivateKey       Code = "INVALID_PRIVATE_KEY"
	CodeInvalidSigningInput     Code = "INVALID_SIGNING_INPUT"
	CodeUnsupportedAlgorithm    Code = "UNSUPPORTED_SIGNATURE_ALGORITHM"
	CodeDuplicateSignatureID    Code = "DUPLICATE_SIGNATURE_ID"
	CodeContextDigestMismatch   Code = "CONTEXT_DIGEST_MISMATCH"
	CodeCanonicalizationFailure Code = "CANONICALIZATION_FAILED"
)

// Error is a stable typed signing failure.
type Error struct {
	Code   Code
	Detail string
	Cause  error
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func fail(code Code, detail string, cause error) *Error {
	return &Error{
		Code:   code,
		Detail: detail,
		Cause:  cause,
	}
}

// ErrorCode returns the stable code carried by a signing error.
func ErrorCode(err error) (Code, bool) {
	var typed *Error
	if !errors.As(err, &typed) {
		return "", false
	}
	return typed.Code, true
}

// Options identifies one deterministic signature statement.
type Options struct {
	SignerID    string
	KeyID       string
	SignatureID string
	SignedAt    string
}

type versionConfig struct {
	contextType       string
	signedContextType string
	statementType     string
}

var versions = map[string]versionConfig{
	"agp.decision-context/1": {
		contextType:       "agp.decision-context/1",
		signedContextType: "agp.signed-decision-context/1",
		statementType:     "agp.signature-statement/1",
	},
	"agp.decision-context/2": {
		contextType:       "agp.decision-context/2",
		signedContextType: "agp.signed-decision-context/2",
		statementType:     "agp.signature-statement/2",
	},
	"agp.decision-context/3": {
		contextType:       "agp.decision-context/3",
		signedContextType: "agp.signed-decision-context/3",
		statementType:     "agp.signature-statement/3",
	},
}

// CanonicalBytes returns the deterministic JSON representation used for
// context digests, signature statements, and serialized signer output.
func CanonicalBytes(value any) ([]byte, error) {
	encoded, err := canonicaljson.Bytes(value)
	if err != nil {
		return nil, fail(
			CodeCanonicalizationFailure,
			err.Error(),
			err,
		)
	}
	return encoded, nil
}

// ParsePrivateKey parses the strict private-key JSON format used by the
// repository signer:
//
//	{"algorithm":"ed25519","private_key":"<unpadded-base64url-seed>"}
func ParsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	value, err := verifyapi.ParseJSON(raw)
	if err != nil {
		return nil, fail(
			CodeInvalidPrivateKey,
			err.Error(),
			err,
		)
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, fail(
			CodeInvalidPrivateKey,
			"private key file must contain an object",
			nil,
		)
	}

	if len(object) != 2 {
		return nil, fail(
			CodeInvalidPrivateKey,
			"private key file must contain exactly algorithm and private_key",
			nil,
		)
	}

	algorithm, algorithmOK := object["algorithm"].(string)
	privateText, privateOK := object["private_key"].(string)

	if !algorithmOK || !privateOK {
		return nil, fail(
			CodeInvalidPrivateKey,
			"private key file must contain exactly algorithm and private_key",
			nil,
		)
	}

	if algorithm != supportedAlgorithm {
		return nil, fail(
			CodeUnsupportedAlgorithm,
			"unsupported private key algorithm: "+algorithm,
			nil,
		)
	}

	if privateText == "" {
		return nil, fail(
			CodeInvalidPrivateKey,
			"private_key must be a non-empty base64url string",
			nil,
		)
	}

	if _, exists := object["algorithm"]; !exists {
		return nil, fail(
			CodeInvalidPrivateKey,
			"missing algorithm",
			nil,
		)
	}
	if _, exists := object["private_key"]; !exists {
		return nil, fail(
			CodeInvalidPrivateKey,
			"missing private_key",
			nil,
		)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(privateText)
	if err != nil {
		return nil, fail(
			CodeInvalidPrivateKey,
			"private_key is not valid unpadded base64url",
			err,
		)
	}

	if base64.RawURLEncoding.EncodeToString(decoded) != privateText {
		return nil, fail(
			CodeInvalidPrivateKey,
			"private_key is not canonical base64url",
			nil,
		)
	}

	if len(decoded) != ed25519.SeedSize {
		return nil, fail(
			CodeInvalidPrivateKey,
			fmt.Sprintf(
				"private_key has %d bytes; expected %d",
				len(decoded),
				ed25519.SeedSize,
			),
			nil,
		)
	}

	return ed25519.NewKeyFromSeed(decoded), nil
}

func cloneMap(value any) (map[string]any, error) {
	encoded, err := CanonicalBytes(value)
	if err != nil {
		return nil, err
	}

	cloned, err := verifyapi.ParseJSON(encoded)
	if err != nil {
		return nil, fail(
			CodeInvalidSigningInput,
			err.Error(),
			err,
		)
	}

	object, ok := cloned.(map[string]any)
	if !ok {
		return nil, fail(
			CodeInvalidSigningInput,
			"signing input must be a JSON object",
			nil,
		)
	}

	return object, nil
}

func resolveContextVersion(context map[string]any) (versionConfig, error) {
	objectType, ok := context["object_type"].(string)
	if !ok {
		return versionConfig{}, fail(
			CodeInvalidSigningInput,
			"context object_type must be a string",
			nil,
		)
	}

	config, ok := versions[objectType]
	if !ok {
		return versionConfig{}, fail(
			CodeInvalidSigningInput,
			"unsupported context object_type: "+objectType,
			nil,
		)
	}

	return config, nil
}

func createEntry(
	context map[string]any,
	privateKey ed25519.PrivateKey,
	options Options,
) (map[string]any, string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, "", fail(
			CodeInvalidPrivateKey,
			fmt.Sprintf(
				"private key has %d bytes; expected %d",
				len(privateKey),
				ed25519.PrivateKeySize,
			),
			nil,
		)
	}

	config, err := resolveContextVersion(context)
	if err != nil {
		return nil, "", err
	}

	contextBytes, err := CanonicalBytes(context)
	if err != nil {
		return nil, "", err
	}

	sum := sha256.Sum256(contextBytes)
	digest := hex.EncodeToString(sum[:])

	statement := map[string]any{
		"object_type":         config.statementType,
		"purpose":             "decision-context-attestation",
		"context_object_type": config.contextType,
		"context_digest": map[string]any{
			"algorithm": "sha-256",
			"value":     digest,
		},
		"signer_id": options.SignerID,
		"key_id":    options.KeyID,
		"algorithm": supportedAlgorithm,
		"signed_at": options.SignedAt,
	}

	statementBytes, err := CanonicalBytes(statement)
	if err != nil {
		return nil, "", err
	}

	signature := ed25519.Sign(privateKey, statementBytes)

	entry := map[string]any{
		"signature_id": options.SignatureID,
		"statement":    statement,
		"signature": base64.RawURLEncoding.EncodeToString(
			signature,
		),
	}

	return entry, digest, nil
}

// Create signs one Decision Context and returns a Signed Decision Context.
func Create(
	context any,
	privateKey ed25519.PrivateKey,
	options Options,
) (map[string]any, error) {
	contextObject, err := cloneMap(context)
	if err != nil {
		return nil, err
	}

	config, err := resolveContextVersion(contextObject)
	if err != nil {
		return nil, err
	}

	entry, digest, err := createEntry(
		contextObject,
		privateKey,
		options,
	)
	if err != nil {
		return nil, err
	}

	result := map[string]any{
		"object_type": config.signedContextType,
		"context":     contextObject,
		"context_digest": map[string]any{
			"algorithm": "sha-256",
			"value":     digest,
		},
		"signatures": []any{entry},
	}

	if _, err := verifyapi.StructuralValidate(result); err != nil {
		return nil, fail(
			CodeInvalidSigningInput,
			err.Error(),
			err,
		)
	}

	return result, nil
}

// Append adds one signature to an existing Signed Decision Context.
func Append(
	signedContext any,
	privateKey ed25519.PrivateKey,
	options Options,
) (map[string]any, error) {
	result, err := cloneMap(signedContext)
	if err != nil {
		return nil, err
	}

	if _, err := verifyapi.StructuralValidate(result); err != nil {
		return nil, fail(
			CodeInvalidSigningInput,
			err.Error(),
			err,
		)
	}

	context, ok := result["context"].(map[string]any)
	if !ok {
		return nil, fail(
			CodeInvalidSigningInput,
			"signed context does not contain a context object",
			nil,
		)
	}

	signatures, ok := result["signatures"].([]any)
	if !ok {
		return nil, fail(
			CodeInvalidSigningInput,
			"signed context signatures must be an array",
			nil,
		)
	}

	for _, raw := range signatures {
		entry, entryOK := raw.(map[string]any)
		if !entryOK {
			continue
		}
		if entry["signature_id"] == options.SignatureID {
			return nil, fail(
				CodeDuplicateSignatureID,
				"signature_id already exists: "+
					options.SignatureID,
				nil,
			)
		}
	}

	entry, digest, err := createEntry(
		context,
		privateKey,
		options,
	)
	if err != nil {
		return nil, err
	}

	digestObject, ok := result["context_digest"].(map[string]any)
	if !ok ||
		digestObject["algorithm"] != "sha-256" ||
		digestObject["value"] != digest {
		return nil, fail(
			CodeContextDigestMismatch,
			"existing context_digest does not match context",
			nil,
		)
	}

	signatures = append(signatures, entry)

	sort.Slice(signatures, func(left, right int) bool {
		leftEntry := signatures[left].(map[string]any)
		rightEntry := signatures[right].(map[string]any)

		leftID, _ := leftEntry["signature_id"].(string)
		rightID, _ := rightEntry["signature_id"].(string)

		return leftID < rightID
	})

	result["signatures"] = signatures

	if _, err := verifyapi.StructuralValidate(result); err != nil {
		return nil, fail(
			CodeInvalidSigningInput,
			err.Error(),
			err,
		)
	}

	return result, nil
}
