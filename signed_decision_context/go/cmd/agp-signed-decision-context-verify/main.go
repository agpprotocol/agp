package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	supportedAlgorithm       = "ed25519"
	maxDepth                 = 64
	minSafeInt         int64 = -(1<<53 - 1)
	maxSafeInt         int64 = 1<<53 - 1
)

var (
	identifierRE = regexp.MustCompile(
		`^[a-z0-9][a-z0-9._:/-]{1,126}[a-z0-9]$`,
	)
	contextIDRE = regexp.MustCompile(
		`^[a-z0-9][a-z0-9._:-]{2,127}$`,
	)
	timestampRE = regexp.MustCompile(
		`^[0-9]{4}-[0-9]{2}-[0-9]{2}T` +
			`[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`,
	)
)

type failure struct {
	code   string
	detail string
	status string
}

func (e *failure) Error() string {
	return e.detail
}

func invalid(code, detail string) error {
	return &failure{
		code:   code,
		detail: detail,
		status: "invalid",
	}
}

func unverified(code, detail string) error {
	return &failure{
		code:   code,
		detail: detail,
		status: "unverified",
	}
}

func parseValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, invalid("INVALID_JSON", "maximum depth exceeded")
	}

	token, err := decoder.Token()
	if err != nil {
		return nil, invalid("INVALID_JSON", err.Error())
	}

	switch value := token.(type) {
	case nil:
		return nil, nil

	case bool:
		return value, nil

	case string:
		if !utf8.ValidString(value) {
			return nil, invalid("INVALID_JSON", "invalid UTF-8 string")
		}
		return value, nil

	case json.Number:
		text := value.String()

		if strings.ContainsAny(text, ".eE") {
			return nil, invalid(
				"INVALID_JSON",
				"non-integer number is not supported: "+text,
			)
		}

		number, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, invalid("INVALID_JSON", "invalid integer")
		}

		if number < minSafeInt || number > maxSafeInt {
			return nil, invalid("INVALID_JSON", "integer outside safe range")
		}

		return number, nil

	case json.Delim:
		switch value {
		case '{':
			result := map[string]any{}

			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, invalid("INVALID_JSON", err.Error())
				}

				key, ok := keyToken.(string)
				if !ok {
					return nil, invalid(
						"INVALID_JSON",
						"object key must be a string",
					)
				}

				if _, exists := result[key]; exists {
					return nil, invalid(
						"INVALID_JSON",
						"duplicate JSON member: "+key,
					)
				}

				child, err := parseValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}

				result[key] = child
			}

			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, invalid(
					"INVALID_JSON",
					"unterminated object",
				)
			}

			return result, nil

		case '[':
			result := []any{}

			for decoder.More() {
				child, err := parseValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}

				result = append(result, child)
			}

			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, invalid(
					"INVALID_JSON",
					"unterminated array",
				)
			}

			return result, nil

		default:
			return nil, invalid(
				"INVALID_JSON",
				"unexpected JSON delimiter",
			)
		}

	default:
		return nil, invalid(
			"INVALID_JSON",
			"unsupported JSON token",
		)
	}
}

func parseJSON(raw []byte) (any, error) {
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, invalid("INVALID_JSON", "UTF-8 BOM is not allowed")
	}

	if !utf8.Valid(raw) {
		return nil, invalid("INVALID_JSON", "invalid UTF-8")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	value, err := parseValue(decoder, 0)
	if err != nil {
		return nil, err
	}

	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, invalid("INVALID_JSON", "trailing JSON data")
		}
		return nil, invalid("INVALID_JSON", err.Error())
	}

	return value, nil
}

func loadJSON(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, invalid("INVALID_JSON", err.Error())
	}

	return parseJSON(raw)
}

func escapeString(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", invalid(
			"INVALID_SIGNATURE_STATEMENT",
			"invalid UTF-8 string",
		)
	}

	var builder strings.Builder
	builder.WriteByte('"')

	for _, current := range value {
		switch current {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\t':
			builder.WriteString(`\t`)
		case '\n':
			builder.WriteString(`\n`)
		case '\f':
			builder.WriteString(`\f`)
		case '\r':
			builder.WriteString(`\r`)
		default:
			if current <= 0x1F {
				builder.WriteString(
					fmt.Sprintf(`\u%04x`, current),
				)
			} else {
				builder.WriteRune(current)
			}
		}
	}

	builder.WriteByte('"')
	return builder.String(), nil
}

func canonicalText(value any, depth int) (string, error) {
	if depth > maxDepth {
		return "", invalid(
			"INVALID_SIGNATURE_STATEMENT",
			"maximum depth exceeded",
		)
	}

	switch item := value.(type) {
	case nil:
		return "null", nil

	case bool:
		if item {
			return "true", nil
		}
		return "false", nil

	case int64:
		if item < minSafeInt || item > maxSafeInt {
			return "", invalid(
				"INVALID_SIGNATURE_STATEMENT",
				"integer outside safe range",
			)
		}
		return strconv.FormatInt(item, 10), nil

	case string:
		return escapeString(item)

	case []any:
		parts := make([]string, len(item))

		for index, child := range item {
			encoded, err := canonicalText(child, depth+1)
			if err != nil {
				return "", err
			}
			parts[index] = encoded
		}

		return "[" + strings.Join(parts, ",") + "]", nil

	case map[string]any:
		keys := make([]string, 0, len(item))

		for key := range item {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		parts := make([]string, 0, len(keys))

		for _, key := range keys {
			encodedKey, err := escapeString(key)
			if err != nil {
				return "", err
			}

			encodedValue, err := canonicalText(
				item[key],
				depth+1,
			)
			if err != nil {
				return "", err
			}

			parts = append(
				parts,
				encodedKey+":"+encodedValue,
			)
		}

		return "{" + strings.Join(parts, ",") + "}", nil

	default:
		return "", invalid(
			"INVALID_SIGNATURE_STATEMENT",
			fmt.Sprintf("unsupported type %T", value),
		)
	}
}

func canonicalBytes(value any) ([]byte, error) {
	text, err := canonicalText(value, 0)
	if err != nil {
		return nil, err
	}

	return []byte(text), nil
}

func exactMembers(value map[string]any, expected ...string) bool {
	if len(value) != len(expected) {
		return false
	}

	for _, field := range expected {
		if _, exists := value[field]; !exists {
			return false
		}
	}

	return true
}

func requireString(
	value map[string]any,
	field string,
	code string,
	detail string,
) (string, error) {
	text, ok := value[field].(string)
	if !ok {
		return "", invalid(code, detail)
	}

	return text, nil
}

func validateDigest(value any) (map[string]any, error) {
	digest, ok := value.(map[string]any)
	if !ok || !exactMembers(digest, "algorithm", "value") {
		return nil, invalid(
			"INVALID_CONTEXT_DIGEST",
			"invalid context digest",
		)
	}

	algorithm, ok := digest["algorithm"].(string)
	if !ok || algorithm != "sha-256" {
		return nil, invalid(
			"INVALID_CONTEXT_DIGEST",
			"invalid context digest",
		)
	}

	hexValue, ok := digest["value"].(string)
	if !ok || len(hexValue) != 64 {
		return nil, invalid(
			"INVALID_CONTEXT_DIGEST",
			"invalid context digest",
		)
	}

	if _, err := hex.DecodeString(hexValue); err != nil ||
		strings.ToLower(hexValue) != hexValue {
		return nil, invalid(
			"INVALID_CONTEXT_DIGEST",
			"invalid context digest",
		)
	}

	return digest, nil
}

func validateStatement(
	value any,
	index int,
	contextDigest map[string]any,
) (map[string]any, error) {
	statement, ok := value.(map[string]any)
	if !ok {
		return nil, invalid(
			"INVALID_SIGNATURE_STATEMENT",
			fmt.Sprintf(
				"signature[%d].statement must be object",
				index,
			),
		)
	}

	expected := []string{
		"object_type",
		"purpose",
		"context_object_type",
		"context_digest",
		"signer_id",
		"key_id",
		"algorithm",
		"signed_at",
	}

	if !exactMembers(statement, expected...) {
		return nil, invalid(
			"INVALID_SIGNATURE_STATEMENT",
			fmt.Sprintf(
				"signature[%d].statement has invalid members",
				index,
			),
		)
	}

	if statement["object_type"] != "agp.signature-statement/1" {
		return nil, invalid(
			"INVALID_SIGNATURE_STATEMENT",
			fmt.Sprintf(
				"signature[%d]: invalid object_type",
				index,
			),
		)
	}

	if statement["purpose"] != "decision-context-attestation" {
		return nil, invalid(
			"INVALID_SIGNATURE_STATEMENT",
			fmt.Sprintf(
				"signature[%d]: invalid purpose",
				index,
			),
		)
	}

	if statement["context_object_type"] != "agp.decision-context/1" {
		return nil, invalid(
			"STATEMENT_CONTEXT_TYPE_MISMATCH",
			fmt.Sprintf(
				"signature[%d] context type mismatch",
				index,
			),
		)
	}

	statementDigest, err := validateDigest(statement["context_digest"])
	if err != nil {
		return nil, invalid(
			"INVALID_SIGNATURE_STATEMENT",
			fmt.Sprintf(
				"signature[%d]: invalid context digest",
				index,
			),
		)
	}

	if statementDigest["algorithm"] != contextDigest["algorithm"] ||
		statementDigest["value"] != contextDigest["value"] {
		return nil, invalid(
			"STATEMENT_CONTEXT_DIGEST_MISMATCH",
			fmt.Sprintf(
				"signature[%d] context digest mismatch",
				index,
			),
		)
	}

	for _, field := range []string{
		"signer_id",
		"key_id",
		"algorithm",
	} {
		text, ok := statement[field].(string)
		if !ok || !identifierRE.MatchString(text) {
			return nil, invalid(
				"INVALID_SIGNATURE_STATEMENT",
				fmt.Sprintf(
					"signature[%d]: invalid %s",
					index,
					field,
				),
			)
		}
	}

	signedAt, ok := statement["signed_at"].(string)
	if !ok || !timestampRE.MatchString(signedAt) {
		return nil, invalid(
			"INVALID_SIGNATURE_STATEMENT",
			fmt.Sprintf(
				"signature[%d]: invalid signed_at",
				index,
			),
		)
	}

	return statement, nil
}

type signatureEntry struct {
	signatureID string
	statement   map[string]any
	signature   string
	orderKey    string
}

type structuralResult struct {
	objectType       string
	contextDigest    map[string]any
	signatureEntries []signatureEntry
}

func structuralValidate(value any) (*structuralResult, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, invalid(
			"INVALID_OBJECT_TYPE",
			"top level must be object",
		)
	}

	if object["object_type"] != "agp.signed-decision-context/1" {
		return nil, invalid(
			"INVALID_OBJECT_TYPE",
			"unexpected object_type",
		)
	}

	if !exactMembers(
		object,
		"object_type",
		"context",
		"context_digest",
		"signatures",
	) {
		for field := range object {
			switch field {
			case "object_type", "context", "context_digest", "signatures":
			default:
				return nil, invalid(
					"UNKNOWN_TOP_LEVEL_MEMBER",
					"unknown top-level member: "+field,
				)
			}
		}

		return nil, invalid(
			"INVALID_OBJECT_TYPE",
			"signed decision context has missing members",
		)
	}

	context, ok := object["context"].(map[string]any)
	if !ok || context["object_type"] != "agp.decision-context/1" {
		return nil, invalid(
			"INVALID_CONTEXT",
			"invalid decision context",
		)
	}

	contextID, ok := context["context_id"].(string)
	if !ok || !contextIDRE.MatchString(contextID) {
		return nil, invalid(
			"INVALID_CONTEXT",
			"context_id is invalid",
		)
	}

	contextDigest, err := validateDigest(object["context_digest"])
	if err != nil {
		return nil, err
	}

	contextBytes, err := canonicalBytes(context)
	if err != nil {
		return nil, invalid("INVALID_CONTEXT", err.Error())
	}

	computedBytes := sha256.Sum256(contextBytes)
	computed := hex.EncodeToString(computedBytes[:])
	declared := contextDigest["value"].(string)

	if declared != computed {
		return nil, invalid(
			"CONTEXT_DIGEST_MISMATCH",
			fmt.Sprintf(
				"declared=%s computed=%s",
				declared,
				computed,
			),
		)
	}

	signatures, ok := object["signatures"].([]any)
	if !ok {
		return nil, invalid(
			"INVALID_SIGNATURE_COLLECTION",
			"signatures must be an array",
		)
	}

	if len(signatures) == 0 {
		return nil, invalid(
			"EMPTY_SIGNATURE_COLLECTION",
			"at least one signature is required",
		)
	}

	entries := make([]signatureEntry, 0, len(signatures))

	for index, rawEntry := range signatures {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return nil, invalid(
				"INVALID_SIGNATURE_ENTRY",
				fmt.Sprintf(
					"signature[%d] must be object",
					index,
				),
			)
		}

		if !exactMembers(
			entry,
			"signature_id",
			"statement",
			"signature",
		) {
			return nil, invalid(
				"INVALID_SIGNATURE_ENTRY",
				fmt.Sprintf(
					"signature[%d] has missing or unknown members",
					index,
				),
			)
		}

		signatureID, ok := entry["signature_id"].(string)
		if !ok || !identifierRE.MatchString(signatureID) {
			return nil, invalid(
				"INVALID_SIGNATURE_ENTRY",
				fmt.Sprintf(
					"signature[%d].signature_id is invalid",
					index,
				),
			)
		}

		statement, err := validateStatement(
			entry["statement"],
			index,
			contextDigest,
		)
		if err != nil {
			return nil, err
		}

		signature, ok := entry["signature"].(string)
		if !ok || signature == "" {
			return nil, invalid(
				"INVALID_SIGNATURE_ENCODING",
				fmt.Sprintf(
					"signature[%d] is not unpadded base64url",
					index,
				),
			)
		}

		for _, current := range signature {
			valid := current >= 'A' && current <= 'Z' ||
				current >= 'a' && current <= 'z' ||
				current >= '0' && current <= '9' ||
				current == '-' ||
				current == '_'

			if !valid {
				return nil, invalid(
					"INVALID_SIGNATURE_ENCODING",
					fmt.Sprintf(
						"signature[%d] is not unpadded base64url",
						index,
					),
				)
			}
		}

		orderKey := strings.Join([]string{
			statement["signer_id"].(string),
			statement["key_id"].(string),
			statement["algorithm"].(string),
			statement["signed_at"].(string),
			signatureID,
		}, "\x00")

		entries = append(entries, signatureEntry{
			signatureID: signatureID,
			statement:   statement,
			signature:   signature,
			orderKey:    orderKey,
		})
	}

	for index := 1; index < len(entries); index++ {
		if entries[index-1].orderKey > entries[index].orderKey {
			return nil, invalid(
				"UNSORTED_SIGNATURES",
				"signatures are not in deterministic order",
			)
		}
	}

	seenIDs := map[string]struct{}{}
	seenExact := map[string]struct{}{}
	seenAttestations := map[string]struct{}{}

	for index, entry := range entries {
		if _, exists := seenIDs[entry.signatureID]; exists {
			return nil, invalid(
				"DUPLICATE_SIGNATURE_ID",
				"duplicate signature_id: "+entry.signatureID,
			)
		}
		seenIDs[entry.signatureID] = struct{}{}

		statementBytes, err := canonicalBytes(entry.statement)
		if err != nil {
			return nil, invalid(
				"INVALID_SIGNATURE_STATEMENT",
				fmt.Sprintf(
					"signature[%d]: %s",
					index,
					err.Error(),
				),
			)
		}

		exactKey := string(statementBytes) + "\x00" + entry.signature
		if _, exists := seenExact[exactKey]; exists {
			return nil, invalid(
				"DUPLICATE_SIGNATURE_ENTRY",
				fmt.Sprintf(
					"duplicate statement and signature at signature[%d]",
					index,
				),
			)
		}
		seenExact[exactKey] = struct{}{}

		digest := entry.statement["context_digest"].(map[string]any)
		attestationKey := strings.Join([]string{
			digest["algorithm"].(string),
			digest["value"].(string),
			entry.statement["signer_id"].(string),
			entry.statement["key_id"].(string),
			entry.statement["algorithm"].(string),
			entry.statement["signed_at"].(string),
		}, "\x00")

		if _, exists := seenAttestations[attestationKey]; exists {
			return nil, invalid(
				"DUPLICATE_ATTESTATION",
				fmt.Sprintf(
					"duplicate semantic attestation at signature[%d]",
					index,
				),
			)
		}
		seenAttestations[attestationKey] = struct{}{}
	}

	return &structuralResult{
		objectType:       object["object_type"].(string),
		contextDigest:    contextDigest,
		signatureEntries: entries,
	}, nil
}

type keyEntry struct {
	signerID  string
	keyID     string
	algorithm string
	publicKey string
}

func loadKeyring(path string) ([]keyEntry, error) {
	value, err := loadJSON(path)
	if err != nil {
		return nil, unverified("INVALID_KEYRING", err.Error())
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, unverified(
			"INVALID_KEYRING",
			"keyring top level must be an object",
		)
	}

	if !exactMembers(object, "keys") {
		return nil, unverified(
			"INVALID_KEYRING",
			"keyring must contain exactly one keys array",
		)
	}

	rawKeys, ok := object["keys"].([]any)
	if !ok {
		return nil, unverified(
			"INVALID_KEYRING",
			"keyring must contain exactly one keys array",
		)
	}

	keys := make([]keyEntry, 0, len(rawKeys))

	for index, rawEntry := range rawKeys {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return nil, unverified(
				"INVALID_KEYRING",
				fmt.Sprintf("keys[%d] must be an object", index),
			)
		}

		if !exactMembers(
			entry,
			"signer_id",
			"key_id",
			"algorithm",
			"public_key",
		) {
			return nil, unverified(
				"INVALID_KEYRING",
				fmt.Sprintf(
					"keys[%d] has missing or unknown members",
					index,
				),
			)
		}

		signerID, okSigner := entry["signer_id"].(string)
		keyID, okKey := entry["key_id"].(string)
		algorithm, okAlgorithm := entry["algorithm"].(string)
		publicKey, okPublicKey := entry["public_key"].(string)

		if !okSigner || !okKey || !okAlgorithm || !okPublicKey {
			return nil, unverified(
				"INVALID_KEYRING",
				fmt.Sprintf(
					"keys[%d] members must be strings",
					index,
				),
			)
		}

		keys = append(keys, keyEntry{
			signerID:  signerID,
			keyID:     keyID,
			algorithm: algorithm,
			publicKey: publicKey,
		})
	}

	return keys, nil
}

func resolveKey(
	keyring []keyEntry,
	signerID string,
	keyID string,
	algorithm string,
) (*keyEntry, error) {
	matches := make([]keyEntry, 0, 1)

	for _, entry := range keyring {
		if entry.signerID == signerID &&
			entry.keyID == keyID &&
			entry.algorithm == algorithm {
			matches = append(matches, entry)
		}
	}

	if len(matches) == 0 {
		return nil, unverified(
			"UNKNOWN_VERIFICATION_KEY",
			fmt.Sprintf(
				"no key for signer_id=%s key_id=%s algorithm=%s",
				signerID,
				keyID,
				algorithm,
			),
		)
	}

	if len(matches) > 1 {
		return nil, unverified(
			"AMBIGUOUS_VERIFICATION_KEY",
			fmt.Sprintf(
				"multiple keys for signer_id=%s key_id=%s algorithm=%s",
				signerID,
				keyID,
				algorithm,
			),
		)
	}

	return &matches[0], nil
}

func decodeCanonicalBase64URL(
	value string,
	code string,
	detailPrefix string,
) ([]byte, error) {
	if value == "" {
		return nil, unverified(
			code,
			detailPrefix+" must be a non-empty base64url string",
		)
	}

	for _, current := range value {
		valid := current >= 'A' && current <= 'Z' ||
			current >= 'a' && current <= 'z' ||
			current >= '0' && current <= '9' ||
			current == '-' ||
			current == '_'

		if !valid {
			return nil, unverified(
				code,
				detailPrefix+" must use unpadded base64url",
			)
		}
	}

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, unverified(
			code,
			detailPrefix+" is not valid base64url",
		)
	}

	canonical := base64.RawURLEncoding.EncodeToString(decoded)
	if canonical != value {
		return nil, unverified(
			code,
			detailPrefix+" is not canonical base64url",
		)
	}

	return decoded, nil
}

func verify(
	value any,
	keyring []keyEntry,
) (map[string]any, error) {
	structural, err := structuralValidate(value)
	if err != nil {
		return nil, err
	}

	verifiedIDs := make([]string, 0, len(structural.signatureEntries))

	for index, entry := range structural.signatureEntries {
		algorithm := entry.statement["algorithm"].(string)

		if algorithm != supportedAlgorithm {
			return nil, unverified(
				"UNSUPPORTED_SIGNATURE_ALGORITHM",
				fmt.Sprintf(
					"signature[%d] algorithm=%s",
					index,
					algorithm,
				),
			)
		}

		key, err := resolveKey(
			keyring,
			entry.statement["signer_id"].(string),
			entry.statement["key_id"].(string),
			algorithm,
		)
		if err != nil {
			return nil, err
		}

		publicKeyBytes, err := decodeCanonicalBase64URL(
			key.publicKey,
			"INVALID_PUBLIC_KEY_ENCODING",
			fmt.Sprintf(
				"keyring public key for signature[%d]",
				index,
			),
		)
		if err != nil {
			return nil, err
		}

		if len(publicKeyBytes) != ed25519.PublicKeySize {
			return nil, unverified(
				"INVALID_PUBLIC_KEY_LENGTH",
				fmt.Sprintf(
					"signature[%d] public key has %d bytes; expected 32",
					index,
					len(publicKeyBytes),
				),
			)
		}

		signatureBytes, err := decodeCanonicalBase64URL(
			entry.signature,
			"INVALID_SIGNATURE_ENCODING",
			fmt.Sprintf("signature[%d]", index),
		)
		if err != nil {
			return nil, err
		}

		if len(signatureBytes) != ed25519.SignatureSize {
			return nil, unverified(
				"INVALID_SIGNATURE_LENGTH",
				fmt.Sprintf(
					"signature[%d] has %d bytes; expected 64",
					index,
					len(signatureBytes),
				),
			)
		}

		message, err := canonicalBytes(entry.statement)
		if err != nil {
			return nil, unverified(
				"INVALID_SIGNATURE_STATEMENT",
				fmt.Sprintf(
					"signature[%d]: %s",
					index,
					err.Error(),
				),
			)
		}

		if !ed25519.Verify(
			ed25519.PublicKey(publicKeyBytes),
			message,
			signatureBytes,
		) {
			return nil, unverified(
				"SIGNATURE_VERIFICATION_FAILED",
				fmt.Sprintf(
					"signature[%d] is invalid",
					index,
				),
			)
		}

		verifiedIDs = append(verifiedIDs, entry.signatureID)
	}

	return map[string]any{
		"status":                   "verified",
		"object_type":              structural.objectType,
		"context_digest":           structural.contextDigest,
		"signature_count":          len(structural.signatureEntries),
		"verified_signature_count": len(verifiedIDs),
		"verified_signature_ids":   verifiedIDs,
	}, nil
}

type arguments struct {
	input          string
	keyring        string
	schemaDir      string
	structuralOnly bool
}

func parseArguments(raw []string) (*arguments, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf(
			"usage: agp-signed-decision-context-verify " +
				"INPUT.json (--structural-only | " +
				"--keyring KEYRING.json) [--schema-dir DIR]",
		)
	}

	result := &arguments{
		input: raw[0],
	}

	for index := 1; index < len(raw); index++ {
		switch raw[index] {
		case "--keyring":
			index++
			if index >= len(raw) {
				return nil, fmt.Errorf("--keyring requires a path")
			}
			result.keyring = raw[index]

		case "--schema-dir":
			index++
			if index >= len(raw) {
				return nil, fmt.Errorf("--schema-dir requires a path")
			}
			result.schemaDir = raw[index]

		case "--structural-only":
			result.structuralOnly = true

		default:
			return nil, fmt.Errorf(
				"unknown argument: %s",
				raw[index],
			)
		}
	}

	if result.structuralOnly && result.keyring != "" {
		return nil, fmt.Errorf(
			"--structural-only and --keyring are mutually exclusive",
		)
	}

	if !result.structuralOnly && result.keyring == "" {
		return nil, fmt.Errorf(
			"--keyring is required unless --structural-only is used",
		)
	}

	return result, nil
}

func writeResult(value map[string]any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func main() {
	args, err := parseArguments(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	value, err := loadJSON(args.input)

	if err == nil && args.structuralOnly {
		var structural *structuralResult
		structural, err = structuralValidate(value)

		if err == nil {
			writeResult(map[string]any{
				"status":          "valid",
				"object_type":     structural.objectType,
				"context_digest":  structural.contextDigest,
				"signature_count": len(structural.signatureEntries),
			})
			return
		}
	}

	if err == nil && !args.structuralOnly {
		var keyring []keyEntry
		keyring, err = loadKeyring(args.keyring)

		if err == nil {
			var result map[string]any
			result, err = verify(value, keyring)

			if err == nil {
				writeResult(result)
				return
			}
		}
	}

	var verificationFailure *failure
	if errors.As(err, &verificationFailure) {
		writeResult(map[string]any{
			"status":     verificationFailure.status,
			"error_code": verificationFailure.code,
			"detail":     verificationFailure.detail,
		})
		os.Exit(1)
	}

	writeResult(map[string]any{
		"status":     "unverified",
		"error_code": "INTERNAL_ERROR",
		"detail":     err.Error(),
	})
	os.Exit(1)
}
