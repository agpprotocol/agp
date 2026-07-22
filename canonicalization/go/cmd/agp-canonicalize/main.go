package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxInputBytes = 1_048_576
	maxDepth      = 64
	minSafeInt    = -(1<<53 - 1)
	maxSafeInt    = 1<<53 - 1
)

type canonicalizationError struct {
	Code   string
	Detail string
}

func (e *canonicalizationError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

type receipt struct {
	Accepted   bool     `json:"accepted"`
	Canonical  *string  `json:"canonical"`
	Digest     *string  `json:"digest"`
	ErrorCodes []string `json:"error_codes"`
}

func fail(code, detail string) error {
	return &canonicalizationError{Code: code, Detail: detail}
}

func parseJSON(raw []byte) (any, error) {
	if len(raw) > maxInputBytes {
		return nil, fail("INPUT_TOO_LARGE", "")
	}
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, fail("UTF8_BOM_NOT_ALLOWED", "")
	}
	if !utf8.Valid(raw) {
		return nil, fail("INVALID_UTF8", "")
	}
	if err := validateSurrogateEscapes(raw); err != nil {
		return nil, err
	}
	if err := validateNonFiniteNumbers(raw); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	value, err := parseValue(decoder, 0)
	if err != nil {
		return nil, err
	}

	token, err := decoder.Token()
	if err == nil {
		_ = token
		return nil, fail("INVALID_JSON", "trailing data")
	}
	if !errors.Is(err, io.EOF) {
		return nil, fail("INVALID_JSON", err.Error())
	}

	return value, nil
}

func validateNonFiniteNumbers(raw []byte) error {
	inString := false
	escaped := false

	for index := 0; index < len(raw); {
		current := raw[index]

		if inString {
			if escaped {
				escaped = false
				index++
				continue
			}
			if current == '\\' {
				escaped = true
				index++
				continue
			}
			if current == '"' {
				inString = false
			}
			index++
			continue
		}

		if current == '"' {
			inString = true
			index++
			continue
		}

		switch {
		case hasTokenAt(raw, index, "-Infinity"):
			return fail("INVALID_NUMBER", "-Infinity")
		case hasTokenAt(raw, index, "Infinity"):
			return fail("INVALID_NUMBER", "Infinity")
		case hasTokenAt(raw, index, "NaN"):
			return fail("INVALID_NUMBER", "NaN")
		default:
			index++
		}
	}

	return nil
}

func hasTokenAt(raw []byte, index int, token string) bool {
	end := index + len(token)
	if end > len(raw) || string(raw[index:end]) != token {
		return false
	}

	if index > 0 && isIdentifierByte(raw[index-1]) {
		return false
	}
	if end < len(raw) && isIdentifierByte(raw[end]) {
		return false
	}

	return true
}

func isIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '_'
}

func validateSurrogateEscapes(raw []byte) error {
	inString := false
	escaped := false

	for index := 0; index < len(raw); index++ {
		current := raw[index]

		if !inString {
			if current == '"' {
				inString = true
			}
			continue
		}

		if escaped {
			escaped = false
			if current != 'u' {
				continue
			}
			if index+4 >= len(raw) {
				return fail("INVALID_JSON", "incomplete unicode escape")
			}

			first, ok := parseHex4(raw[index+1 : index+5])
			if !ok {
				return fail("INVALID_JSON", "invalid unicode escape")
			}
			index += 4

			if first >= 0xD800 && first <= 0xDBFF {
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return fail("INVALID_UNICODE", "unpaired high surrogate")
				}
				second, ok := parseHex4(raw[index+3 : index+7])
				if !ok || second < 0xDC00 || second > 0xDFFF {
					return fail("INVALID_UNICODE", "unpaired high surrogate")
				}
				index += 6
				continue
			}

			if first >= 0xDC00 && first <= 0xDFFF {
				return fail("INVALID_UNICODE", "unpaired low surrogate")
			}
			continue
		}

		if current == '\\' {
			escaped = true
			continue
		}
		if current == '"' {
			inString = false
		}
	}

	return nil
}

func parseHex4(raw []byte) (rune, bool) {
	if len(raw) != 4 {
		return 0, false
	}

	var value rune
	for _, current := range raw {
		value <<= 4
		switch {
		case current >= '0' && current <= '9':
			value += rune(current - '0')
		case current >= 'a' && current <= 'f':
			value += rune(current-'a') + 10
		case current >= 'A' && current <= 'F':
			value += rune(current-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func parseValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fail("MAX_DEPTH_EXCEEDED", "")
	}

	token, err := decoder.Token()
	if err != nil {
		return nil, fail("INVALID_JSON", err.Error())
	}

	switch value := token.(type) {
	case nil:
		return nil, nil
	case bool:
		return value, nil
	case string:
		if err := validateString(value); err != nil {
			return nil, err
		}
		return value, nil
	case json.Number:
		text := value.String()
		if strings.ContainsAny(text, ".eE") {
			return nil, fail("DECIMAL_NOT_SUPPORTED", text)
		}
		number, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fail("INTEGER_OUT_OF_RANGE", text)
		}
		if number < minSafeInt || number > maxSafeInt {
			return nil, fail("INTEGER_OUT_OF_RANGE", text)
		}
		return number, nil
	case json.Delim:
		switch value {
		case '{':
			result := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, fail("INVALID_JSON", err.Error())
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fail("INVALID_JSON", "object key is not a string")
				}
				if err := validateString(key); err != nil {
					return nil, err
				}
				if _, exists := result[key]; exists {
					return nil, fail("DUPLICATE_KEY", key)
				}
				item, err := parseValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				result[key] = item
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fail("INVALID_JSON", "unterminated object")
			}
			return result, nil
		case '[':
			result := []any{}
			for decoder.More() {
				item, err := parseValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				result = append(result, item)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fail("INVALID_JSON", "unterminated array")
			}
			return result, nil
		default:
			return nil, fail("INVALID_JSON", "unexpected delimiter")
		}
	default:
		return nil, fail("INVALID_JSON", "unsupported token")
	}
}

func validateString(value string) error {
	if !utf8.ValidString(value) {
		return fail("INVALID_UNICODE", "")
	}
	for _, r := range value {
		if r >= 0xD800 && r <= 0xDFFF {
			return fail("INVALID_UNICODE", fmt.Sprintf("surrogate U+%04X", r))
		}
	}
	return nil
}

func escapeString(value string) (string, error) {
	if err := validateString(value); err != nil {
		return "", err
	}

	var builder strings.Builder
	builder.WriteByte('"')

	for _, r := range value {
		switch r {
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
			if r <= 0x1F {
				builder.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				builder.WriteRune(r)
			}
		}
	}

	builder.WriteByte('"')
	return builder.String(), nil
}

func canonicalText(value any, depth int) (string, error) {
	if depth > maxDepth {
		return "", fail("MAX_DEPTH_EXCEEDED", "")
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
			return "", fail("INTEGER_OUT_OF_RANGE", "")
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
			escapedKey, err := escapeString(key)
			if err != nil {
				return "", err
			}
			encodedValue, err := canonicalText(item[key], depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, escapedKey+":"+encodedValue)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", fail("UNSUPPORTED_TYPE", fmt.Sprintf("%T", value))
	}
}

func canonicalBytes(value any) ([]byte, error) {
	text, err := canonicalText(value, 0)
	if err != nil {
		return nil, err
	}
	return []byte(text), nil
}

func makeReceipt(raw []byte) receipt {
	value, err := parseJSON(raw)
	if err != nil {
		code := "INVALID_JSON"
		var canonicalErr *canonicalizationError
		if errors.As(err, &canonicalErr) {
			code = canonicalErr.Code
		}
		return receipt{
			Accepted:   false,
			Canonical:  nil,
			Digest:     nil,
			ErrorCodes: []string{code},
		}
	}

	encoded, err := canonicalBytes(value)
	if err != nil {
		code := "INVALID_JSON"
		var canonicalErr *canonicalizationError
		if errors.As(err, &canonicalErr) {
			code = canonicalErr.Code
		}
		return receipt{
			Accepted:   false,
			Canonical:  nil,
			Digest:     nil,
			ErrorCodes: []string{code},
		}
	}

	canonical := string(encoded)
	sum := sha256.Sum256(encoded)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	return receipt{
		Accepted:   true,
		Canonical:  &canonical,
		Digest:     &digest,
		ErrorCodes: []string{},
	}
}

func encodeReceipt(value receipt) ([]byte, error) {
	var builder bytes.Buffer
	writer := bufio.NewWriter(&builder)

	canonicalMap := map[string]any{
		"accepted":    value.Accepted,
		"canonical":   value.Canonical,
		"digest":      value.Digest,
		"error_codes": value.ErrorCodes,
	}

	encoded, err := canonicalReceiptValue(canonicalMap)
	if err != nil {
		return nil, err
	}

	if _, err := writer.WriteString(encoded); err != nil {
		return nil, err
	}
	if err := writer.WriteByte('\n'); err != nil {
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		return nil, err
	}
	return builder.Bytes(), nil
}

func canonicalReceiptValue(value any) (string, error) {
	switch item := value.(type) {
	case nil:
		return "null", nil
	case bool:
		if item {
			return "true", nil
		}
		return "false", nil
	case string:
		return escapeString(item)
	case *string:
		if item == nil {
			return "null", nil
		}
		return escapeString(*item)
	case []string:
		parts := make([]string, len(item))
		for i, child := range item {
			encoded, err := escapeString(child)
			if err != nil {
				return "", err
			}
			parts[i] = encoded
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
			encodedValue, err := canonicalReceiptValue(item[key])
			if err != nil {
				return "", err
			}
			parts = append(parts, encodedKey+":"+encodedValue)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", fail("UNSUPPORTED_TYPE", fmt.Sprintf("%T", value))
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: agp-canonicalize INPUT.json OUTPUT.json")
		os.Exit(2)
	}

	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read input: %v\n", err)
		os.Exit(2)
	}

	result := makeReceipt(raw)
	encoded, err := encodeReceipt(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot encode receipt: %v\n", err)
		os.Exit(2)
	}

	if err := os.WriteFile(os.Args[2], encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write output: %v\n", err)
		os.Exit(2)
	}
}
