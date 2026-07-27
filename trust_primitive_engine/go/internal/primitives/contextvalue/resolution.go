package contextvalue

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

const (
	maxSafeInteger       = int64(9007199254740991)
	maxContextPathLength = 512
	maxContextSegments   = 16
	contextPathPrefix    = "/proposal/payload/"
)

type Resolution struct {
	Status    string
	ValueType string
	Value     any
}

func decodeSegment(segment string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(segment); {
		if segment[index] != '~' {
			result.WriteByte(segment[index])
			index++
			continue
		}
		if index+1 >= len(segment) {
			return "", errors.New("context path contains an incomplete escape")
		}
		switch segment[index+1] {
		case '0':
			result.WriteByte('~')
		case '1':
			result.WriteByte('/')
		default:
			return "", errors.New("context path contains an unsupported escape")
		}
		index += 2
	}
	return result.String(), nil
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validateIndexLikeSegment(segment string) error {
	if segment == "-" {
		return errors.New("context path array append token is forbidden")
	}
	if strings.HasPrefix(segment, "-") &&
		len(segment) > 1 &&
		allDigits(segment[1:]) {
		return errors.New("context path negative indexes are forbidden")
	}
	if !allDigits(segment) {
		return nil
	}
	if len(segment) > 1 && segment[0] == '0' {
		return errors.New("context path array indexes must be canonical")
	}
	value, err := strconv.ParseUint(segment, 10, 64)
	if err != nil || value > uint64(maxSafeInteger) {
		return errors.New("context path array index exceeds safe integer")
	}
	return nil
}

func ParsePath(path string) ([]string, error) {
	length := utf8.RuneCountInString(path)
	if length < utf8.RuneCountInString(contextPathPrefix) ||
		length > maxContextPathLength {
		return nil, errors.New(
			"context path length is outside the allowed range",
		)
	}
	if !strings.HasPrefix(path, contextPathPrefix) {
		return nil, errors.New(
			"context path must begin with /proposal/payload/",
		)
	}

	encoded := strings.Split(
		strings.TrimPrefix(path, contextPathPrefix),
		"/",
	)
	if len(encoded) < 1 || len(encoded) > maxContextSegments {
		return nil, errors.New(
			"context path has an invalid descendant segment count",
		)
	}

	decoded := make([]string, 0, len(encoded))
	for _, item := range encoded {
		if item == "" {
			return nil, errors.New(
				"context path must contain non-empty descendant segments",
			)
		}
		segment, err := decodeSegment(item)
		if err != nil {
			return nil, err
		}
		if segment == "" {
			return nil, errors.New("context path decoded to an empty segment")
		}
		if err := validateIndexLikeSegment(segment); err != nil {
			return nil, err
		}
		decoded = append(decoded, segment)
	}
	return decoded, nil
}

func valueType(value any) (string, any, error) {
	switch typed := value.(type) {
	case nil:
		return "null", nil, nil
	case bool:
		return "boolean", typed, nil
	case string:
		return "string", typed, nil
	case int:
		if int64(typed) < -maxSafeInteger ||
			int64(typed) > maxSafeInteger {
			return "", nil, errors.New(
				"context integer exceeds safe integer range",
			)
		}
		return "integer", typed, nil
	case int64:
		if typed < -maxSafeInteger || typed > maxSafeInteger {
			return "", nil, errors.New(
				"context integer exceeds safe integer range",
			)
		}
		return "integer", typed, nil
	case json.Number:
		integer, err := typed.Int64()
		if err != nil ||
			integer < -maxSafeInteger ||
			integer > maxSafeInteger {
			return "", nil, errors.New(
				"context value is not a safe integer",
			)
		}
		return "integer", integer, nil
	case map[string]any:
		return "object", nil, nil
	case []any:
		return "array", nil, nil
	default:
		return "", nil, fmt.Errorf(
			"unsupported projected context value type: %T",
			value,
		)
	}
}

func ResolvePath(ctx model.Context, path string) (Resolution, error) {
	segments, err := ParsePath(path)
	if err != nil {
		return Resolution{}, err
	}

	var current any = ctx.Proposal.Payload
	if current == nil {
		return Resolution{Status: "missing"}, nil
	}

	for _, segment := range segments {
		switch typed := current.(type) {
		case map[string]any:
			next, present := typed[segment]
			if !present {
				return Resolution{Status: "missing"}, nil
			}
			current = next
		case []any:
			if !allDigits(segment) {
				return Resolution{Status: "type_mismatch"}, nil
			}
			indexValue, err := strconv.ParseUint(segment, 10, 64)
			if err != nil {
				return Resolution{Status: "missing"}, nil
			}
			if indexValue >= uint64(len(typed)) {
				return Resolution{Status: "missing"}, nil
			}
			current = typed[int(indexValue)]
		default:
			return Resolution{Status: "type_mismatch"}, nil
		}
	}

	kind, value, err := valueType(current)
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{
		Status:    "found",
		ValueType: kind,
		Value:     value,
	}, nil
}
