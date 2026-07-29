// Package canonicaljson provides the deterministic JSON encoding used by
// Signed Decision Context signing and verification.
package canonicaljson

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxDepth         = 64
	minSafeInt int64 = -(1<<53 - 1)
	maxSafeInt int64 = 1<<53 - 1
)

// Error reports a deterministic canonicalization failure.
type Error struct {
	Detail string
}

func (e *Error) Error() string {
	return e.Detail
}

func fail(detail string) error {
	return &Error{Detail: detail}
}

func escapeString(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", fail("invalid UTF-8 string")
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
		return "", fail("maximum depth exceeded")
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
			return "", fail("integer outside safe range")
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
		return "", fail(
			fmt.Sprintf("unsupported type %T", value),
		)
	}
}

// Bytes returns the deterministic canonical JSON representation of value.
func Bytes(value any) ([]byte, error) {
	text, err := canonicalText(value, 0)
	if err != nil {
		return nil, err
	}

	return []byte(text), nil
}
