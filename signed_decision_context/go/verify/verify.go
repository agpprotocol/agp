package verify

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
	evidenceTypeRE = regexp.MustCompile(
		`^[a-z0-9][a-z0-9._:/-]{1,123}[a-z0-9]/[1-9][0-9]*$`,
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

type versionConfig struct {
	signedType    string
	contextType   string
	statementType string
}

func resolveVersionConfig(objectType any) (*versionConfig, error) {
	value, ok := objectType.(string)
	if !ok {
		return nil, invalid("INVALID_OBJECT_TYPE", "unexpected object_type")
	}

	configs := map[string]versionConfig{
		"agp.signed-decision-context/1": {
			signedType:    "agp.signed-decision-context/1",
			contextType:   "agp.decision-context/1",
			statementType: "agp.signature-statement/1",
		},
		"agp.signed-decision-context/2": {
			signedType:    "agp.signed-decision-context/2",
			contextType:   "agp.decision-context/2",
			statementType: "agp.signature-statement/2",
		},
		"agp.signed-decision-context/3": {
			signedType:    "agp.signed-decision-context/3",
			contextType:   "agp.decision-context/3",
			statementType: "agp.signature-statement/3",
		},
	}

	config, exists := configs[value]
	if !exists {
		return nil, invalid("INVALID_OBJECT_TYPE", "unexpected object_type")
	}
	return &config, nil
}

func validateContextForVersion(
	value any,
	config *versionConfig,
) (map[string]any, error) {
	context, ok := value.(map[string]any)
	if !ok || context["object_type"] != config.contextType {
		return nil, invalid(
			"INVALID_CONTEXT",
			"context object_type must be "+config.contextType,
		)
	}

	contextID, ok := context["context_id"].(string)
	if !ok || !contextIDRE.MatchString(contextID) {
		return nil, invalid("INVALID_CONTEXT", "context_id is invalid")
	}

	if config.contextType == "agp.decision-context/2" ||
		config.contextType == "agp.decision-context/3" {
		evaluationTime, ok := context["evaluation_time"].(int64)
		if !ok || evaluationTime < 0 || evaluationTime > maxSafeInt {
			return nil, invalid(
				"INVALID_CONTEXT",
				"evaluation_time must be a non-negative safe integer",
			)
		}
	}

	if config.contextType == "agp.decision-context/3" {
		evidence, ok := context["evidence"].([]any)
		if !ok {
			return nil, invalid("INVALID_CONTEXT", "evidence must be an array")
		}

		for index, raw := range evidence {
			entry, ok := raw.(map[string]any)
			if !ok || !exactMembers(
				entry,
				"id",
				"digest",
				"media_type",
				"evidence_type",
				"issuer_id",
			) {
				return nil, invalid(
					"INVALID_CONTEXT",
					fmt.Sprintf("evidence[%d] has invalid members", index),
				)
			}

			for _, field := range []string{"id", "issuer_id"} {
				fieldValue, ok := entry[field].(string)
				if !ok || !identifierRE.MatchString(fieldValue) {
					return nil, invalid(
						"INVALID_CONTEXT",
						fmt.Sprintf("evidence[%d].%s is invalid", index, field),
					)
				}
			}

			digest, ok := entry["digest"].(string)
			if !ok || len(digest) != 64 {
				return nil, invalid(
					"INVALID_CONTEXT",
					fmt.Sprintf("evidence[%d].digest is invalid", index),
				)
			}
			if _, err := hex.DecodeString(digest); err != nil ||
				strings.ToLower(digest) != digest {
				return nil, invalid(
					"INVALID_CONTEXT",
					fmt.Sprintf("evidence[%d].digest is invalid", index),
				)
			}

			evidenceType, ok := entry["evidence_type"].(string)
			if !ok || len(evidenceType) > 128 ||
				!evidenceTypeRE.MatchString(evidenceType) {
				return nil, invalid(
					"INVALID_CONTEXT",
					fmt.Sprintf("evidence[%d].evidence_type is invalid", index),
				)
			}
		}
	}

	return context, nil
}

func validateStatement(
	value any,
	index int,
	contextDigest map[string]any,
	config *versionConfig,
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

	if statement["object_type"] != config.statementType {
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

	if statement["context_object_type"] != config.contextType {
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

	config, err := resolveVersionConfig(object["object_type"])
	if err != nil {
		return nil, err
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

	context, err := validateContextForVersion(
		object["context"],
		config,
	)
	if err != nil {
		return nil, err
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
			config,
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

func parseKeyringValue(value any) ([]keyEntry, error) {
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

func loadKeyring(path string) ([]keyEntry, error) {
	value, err := loadJSON(path)
	if err != nil {
		return nil, unverified("INVALID_KEYRING", err.Error())
	}
	return parseKeyringValue(value)
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

// VerificationResult is the typed reusable signature-verification projection.
type VerificationResult struct {
	Status                 string
	ObjectType             string
	ContextDigest          any
	SignatureCount         int
	VerifiedSignatureCount int
	VerifiedSignatureIDs   []string
}

// StructuralResult is the stable reusable structural-validation projection.
type StructuralResult struct {
	ObjectType     string
	ContextDigest  any
	SignatureCount int
}

// Keyring is an opaque validated verification-key collection.
type Keyring struct {
	entries []keyEntry
}

// LoadJSON loads one strict JSON document with the same rules as the CLI.
func LoadJSON(path string) (any, error) {
	return loadJSON(path)
}

// ParseJSON parses strict JSON bytes with the same rules as the CLI.
func ParseJSON(raw []byte) (any, error) {
	return parseJSON(raw)
}

// StructuralValidate validates a signed decision context without verifying
// signatures.
func StructuralValidate(value any) (StructuralResult, error) {
	result, err := structuralValidate(value)
	if err != nil {
		return StructuralResult{}, err
	}
	return StructuralResult{
		ObjectType:     result.objectType,
		ContextDigest:  result.contextDigest,
		SignatureCount: len(result.signatureEntries),
	}, nil
}

// ParseKeyring parses and validates a strict JSON keyring without filesystem
// dependencies.
func ParseKeyring(raw []byte) (Keyring, error) {
	value, err := parseJSON(raw)
	if err != nil {
		return Keyring{}, unverified("INVALID_KEYRING", err.Error())
	}
	entries, err := parseKeyringValue(value)
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{entries: entries}, nil
}

// LoadKeyring loads and validates a verification keyring.
func LoadKeyring(path string) (Keyring, error) {
	entries, err := loadKeyring(path)
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{entries: entries}, nil
}

// VerifyTyped performs deterministic structural and Ed25519 verification and
// returns a stable typed result.
func VerifyTyped(value any, keyring Keyring) (VerificationResult, error) {
	raw, err := verify(value, keyring.entries)
	if err != nil {
		return VerificationResult{}, err
	}

	ids, _ := raw["verified_signature_ids"].([]string)
	return VerificationResult{
		Status:                 raw["status"].(string),
		ObjectType:             raw["object_type"].(string),
		ContextDigest:          raw["context_digest"],
		SignatureCount:         raw["signature_count"].(int),
		VerifiedSignatureCount: raw["verified_signature_count"].(int),
		VerifiedSignatureIDs:   append([]string(nil), ids...),
	}, nil
}

// Verify preserves the original map-shaped compatibility API.
func Verify(value any, keyring Keyring) (map[string]any, error) {
	result, err := VerifyTyped(value, keyring)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"status":                   result.Status,
		"object_type":              result.ObjectType,
		"context_digest":           result.ContextDigest,
		"signature_count":          result.SignatureCount,
		"verified_signature_count": result.VerifiedSignatureCount,
		"verified_signature_ids":   result.VerifiedSignatureIDs,
	}, nil
}

// FailureDetails exposes the stable CLI failure projection without exposing
// implementation details.
func FailureDetails(err error) (
	status string,
	code string,
	detail string,
	ok bool,
) {
	var item *failure
	if !errors.As(err, &item) {
		return "", "", "", false
	}
	return item.status, item.code, item.detail, true
}
