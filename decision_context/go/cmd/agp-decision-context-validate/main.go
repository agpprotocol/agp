package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const safeMax int64 = 9007199254740991

var (
	identifierRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$`)
	contextIDRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{2,127}$`)
	digestRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	timestampRE  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	mediaTypeRE  = regexp.MustCompile(`^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$`)
)

var topLevel = setOf(
	"object_type", "context_id", "created_at", "expires_at",
	"policy", "proposal", "participants", "evidence", "constraints",
)

var roles = setOf("proposer", "voter", "reviewer", "approver", "observer")

var reservedResultMembers = setOf(
	"decision", "result", "outcome", "accepted", "approved",
	"rejected", "resolution", "execution_state",
)

type validationError struct {
	code   string
	detail string
}

func (e *validationError) Error() string { return e.detail }

func reject(code, detail string) error {
	return &validationError{code: code, detail: detail}
}

type receipt struct {
	Accepted  bool    `json:"accepted"`
	Detail    *string `json:"detail"`
	ErrorCode *string `json:"error_code"`
}

func setOf(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func parseValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, reject("INVALID_JSON", err.Error())
	}

	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			result := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, reject("INVALID_JSON", err.Error())
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, reject("INVALID_JSON", "object key must be a string")
				}
				if _, exists := result[key]; exists {
					return nil, reject("INVALID_JSON", "duplicate JSON member: "+key)
				}
				child, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				result[key] = child
			}
			if _, err := dec.Token(); err != nil {
				return nil, reject("INVALID_JSON", err.Error())
			}
			return result, nil
		case '[':
			result := []any{}
			for dec.More() {
				child, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				result = append(result, child)
			}
			if _, err := dec.Token(); err != nil {
				return nil, reject("INVALID_JSON", err.Error())
			}
			return result, nil
		default:
			return nil, reject("INVALID_JSON", "unexpected delimiter")
		}
	case json.Number:
		text := value.String()
		if strings.ContainsAny(text, ".eE") {
			return nil, reject("INVALID_JSON", "non-integer number is not supported: "+text)
		}
		number, err := value.Int64()
		if err != nil {
			return nil, reject("INVALID_JSON", "invalid integer")
		}
		return number, nil
	default:
		return value, nil
	}
}

func parseJSON(raw []byte) (any, error) {
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, reject("INVALID_JSON", "UTF-8 BOM is not allowed")
	}
	if !utf8.Valid(raw) {
		return nil, reject("INVALID_JSON", "invalid UTF-8")
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, reject("INVALID_JSON", "trailing JSON data")
		}
		return nil, reject("INVALID_JSON", err.Error())
	}
	return value, nil
}

func exactObject(value any, fields map[string]struct{}, code, where string) (map[string]any, error) {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, reject(code, where+" must be an object")
	}
	if len(obj) != len(fields) {
		return nil, reject(code, where+" has invalid fields")
	}
	for field := range fields {
		if _, ok := obj[field]; !ok {
			return nil, reject(code, where+" has invalid fields")
		}
	}
	return obj, nil
}

func identifier(value any, where string) (string, error) {
	text, ok := value.(string)
	if !ok || !identifierRE.MatchString(text) {
		return "", reject("INVALID_IDENTIFIER", where+" is not a valid identifier")
	}
	return text, nil
}

func positiveSafeInteger(value any, where string) (int64, error) {
	number, ok := value.(int64)
	if !ok || number < 1 || number > safeMax {
		return 0, reject("INVALID_SAFE_INTEGER", where+" must be a positive safe integer")
	}
	return number, nil
}

func timestamp(value any, where string) (time.Time, error) {
	text, ok := value.(string)
	if !ok || !timestampRE.MatchString(text) {
		return time.Time{}, reject("INVALID_TIMESTAMP", where+" must be a whole-second UTC timestamp")
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", text)
	if err != nil {
		return time.Time{}, reject("INVALID_TIMESTAMP", where+" is not a valid calendar timestamp")
	}
	return parsed, nil
}

func validateSortedUnique(entries []map[string]any, collection string) error {
	ids := make([]string, 0, len(entries))
	seen := map[string]struct{}{}
	for _, entry := range entries {
		id := entry["id"].(string)
		if _, exists := seen[id]; exists {
			return reject("DUPLICATE_IDENTIFIER", collection+" contains duplicate identifiers")
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sortedIDs := append([]string(nil), ids...)
	sort.Strings(sortedIDs)
	for index := range ids {
		if ids[index] != sortedIDs[index] {
			return reject("UNSORTED_COLLECTION", collection+" must be sorted by id")
		}
	}
	return nil
}

func validateObject(value any) error {
	obj, ok := value.(map[string]any)
	if !ok {
		return reject("INVALID_OBJECT", "decision context must be an object")
	}

	for key := range obj {
		if _, allowed := topLevel[key]; !allowed {
			return reject("UNKNOWN_TOP_LEVEL_MEMBER", "unknown top-level member: "+key)
		}
	}
	if len(obj) != len(topLevel) {
		return reject("INVALID_OBJECT", "decision context is missing required top-level members")
	}
	for field := range topLevel {
		if _, ok := obj[field]; !ok {
			return reject("INVALID_OBJECT", "decision context is missing required top-level members")
		}
	}

	if objectType, ok := obj["object_type"].(string); !ok || objectType != "agp.decision-context/1" {
		return reject("INVALID_OBJECT_TYPE", "object_type must be agp.decision-context/1")
	}
	contextID, ok := obj["context_id"].(string)
	if !ok || !contextIDRE.MatchString(contextID) {
		return reject("INVALID_CONTEXT_ID", "context_id is invalid")
	}

	created, err := timestamp(obj["created_at"], "created_at")
	if err != nil {
		return err
	}
	if obj["expires_at"] != nil {
		expires, err := timestamp(obj["expires_at"], "expires_at")
		if err != nil {
			return err
		}
		if !expires.After(created) {
			return reject("INVALID_TIMESTAMP", "expires_at must be later than created_at")
		}
	}

	policy, err := exactObject(obj["policy"], setOf("id", "version", "digest"), "INVALID_POLICY", "policy")
	if err != nil {
		return err
	}
	if _, err := identifier(policy["id"], "policy.id"); err != nil {
		return err
	}
	if _, err := positiveSafeInteger(policy["version"], "policy.version"); err != nil {
		return err
	}
	policyDigest, ok := policy["digest"].(string)
	if !ok || !digestRE.MatchString(policyDigest) {
		return reject("INVALID_POLICY", "policy.digest must be lowercase SHA-256 hex")
	}

	proposal, err := exactObject(obj["proposal"], setOf("type", "payload"), "INVALID_PROPOSAL", "proposal")
	if err != nil {
		return err
	}
	if _, err := identifier(proposal["type"], "proposal.type"); err != nil {
		return err
	}
	payload, ok := proposal["payload"].(map[string]any)
	if !ok {
		return reject("INVALID_PROPOSAL", "proposal.payload must be an object")
	}
	for member := range payload {
		if _, reserved := reservedResultMembers[member]; reserved {
			return reject("RESERVED_RESULT_MEMBER", "reserved proposal member: "+member)
		}
	}

	participantsRaw, ok := obj["participants"].([]any)
	if !ok || len(participantsRaw) == 0 {
		return reject("INVALID_PARTICIPANTS", "participants must be a non-empty array")
	}
	participants := make([]map[string]any, 0, len(participantsRaw))
	for index, raw := range participantsRaw {
		where := fmt.Sprintf("participants[%d]", index)
		entry, err := exactObject(raw, setOf("id", "role", "weight"), "INVALID_PARTICIPANTS", where)
		if err != nil {
			return err
		}
		if _, err := identifier(entry["id"], where+".id"); err != nil {
			return err
		}
		role, ok := entry["role"].(string)
		if !ok {
			return reject("INVALID_PARTICIPANTS", where+".role is invalid")
		}
		if _, valid := roles[role]; !valid {
			return reject("INVALID_PARTICIPANTS", where+".role is invalid")
		}
		if _, err := positiveSafeInteger(entry["weight"], where+".weight"); err != nil {
			return err
		}
		participants = append(participants, entry)
	}
	if err := validateSortedUnique(participants, "participants"); err != nil {
		return err
	}

	evidenceRaw, ok := obj["evidence"].([]any)
	if !ok {
		return reject("INVALID_EVIDENCE", "evidence must be an array")
	}
	evidence := make([]map[string]any, 0, len(evidenceRaw))
	for index, raw := range evidenceRaw {
		where := fmt.Sprintf("evidence[%d]", index)
		entry, err := exactObject(raw, setOf("id", "digest", "media_type"), "INVALID_EVIDENCE", where)
		if err != nil {
			return err
		}
		if _, err := identifier(entry["id"], where+".id"); err != nil {
			return err
		}
		digest, ok := entry["digest"].(string)
		if !ok || !digestRE.MatchString(digest) {
			return reject("INVALID_EVIDENCE", where+".digest is invalid")
		}
		mediaType, ok := entry["media_type"].(string)
		if !ok || !mediaTypeRE.MatchString(mediaType) {
			return reject("INVALID_EVIDENCE", where+".media_type is invalid")
		}
		evidence = append(evidence, entry)
	}
	if err := validateSortedUnique(evidence, "evidence"); err != nil {
		return err
	}

	constraintsRaw, ok := obj["constraints"].([]any)
	if !ok {
		return reject("INVALID_CONSTRAINTS", "constraints must be an array")
	}
	constraints := make([]map[string]any, 0, len(constraintsRaw))
	for index, raw := range constraintsRaw {
		where := fmt.Sprintf("constraints[%d]", index)
		entry, err := exactObject(raw, setOf("id", "kind", "parameters"), "INVALID_CONSTRAINTS", where)
		if err != nil {
			return err
		}
		if _, err := identifier(entry["id"], where+".id"); err != nil {
			return err
		}
		if _, err := identifier(entry["kind"], where+".kind"); err != nil {
			return err
		}
		if _, ok := entry["parameters"].(map[string]any); !ok {
			return reject("INVALID_CONSTRAINTS", where+".parameters must be an object")
		}
		constraints = append(constraints, entry)
	}
	return validateSortedUnique(constraints, "constraints")
}

func validate(raw []byte) receipt {
	value, err := parseJSON(raw)
	if err == nil {
		err = validateObject(value)
	}
	if err == nil {
		return receipt{Accepted: true}
	}
	validationErr, ok := err.(*validationError)
	if !ok {
		code := "INVALID_OBJECT"
		detail := err.Error()
		return receipt{Accepted: false, Detail: &detail, ErrorCode: &code}
	}
	return receipt{
		Accepted:  false,
		Detail:    &validationErr.detail,
		ErrorCode: &validationErr.code,
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: agp-decision-context-validate <context.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result := validate(raw)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !result.Accepted {
		os.Exit(1)
	}
}
