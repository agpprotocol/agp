package contextvalue

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

const (
	TypeValuePresent = "context_value_present"
	TypeValueEquals  = "context_value_equals"
	TypeValueIn      = "context_value_in"
	TypePathEquals   = "context_path_equals"
	TypeIntegerLeast = "context_integer_at_least"
	TypeIntegerMost  = "context_integer_at_most"

	maxExpectedStringLength = 4096
	maxResultStringLength   = 4096
)

func SafeInteger(value any, field string) (int64, error) {
	switch typed := value.(type) {
	case bool:
		return 0, fmt.Errorf("%s must be an integer", field)
	case json.Number:
		integer, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", field)
		}
		if integer < -maxSafeInteger || integer > maxSafeInteger {
			return 0, fmt.Errorf("%s exceeds safe integer range", field)
		}
		return integer, nil
	case int:
		integer := int64(typed)
		if integer < -maxSafeInteger || integer > maxSafeInteger {
			return 0, fmt.Errorf("%s exceeds safe integer range", field)
		}
		return integer, nil
	case int64:
		if typed < -maxSafeInteger || typed > maxSafeInteger {
			return 0, fmt.Errorf("%s exceeds safe integer range", field)
		}
		return typed, nil
	default:
		return 0, fmt.Errorf("%s must be an integer", field)
	}
}

func scalarType(value any) (string, any, error) {
	switch typed := value.(type) {
	case nil:
		return "null", nil, nil
	case bool:
		return "boolean", typed, nil
	case string:
		return "string", typed, nil
	default:
		integer, err := SafeInteger(value, "value")
		if err == nil {
			return "integer", integer, nil
		}
		return "", nil, errors.New(
			"value must be null, boolean, integer, or string",
		)
	}
}

func scalarSetValues(value any) ([]any, error) {
	switch typed := value.(type) {
	case []any:
		return append([]any(nil), typed...), nil
	case []string:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = item
		}
		return result, nil
	default:
		return nil, errors.New("values must be an array")
	}
}

func compareCanonicalScalars(kind string, left any, right any) int {
	switch kind {
	case "null":
		return 0
	case "boolean":
		leftValue := left.(bool)
		rightValue := right.(bool)
		if leftValue == rightValue {
			return 0
		}
		if !leftValue {
			return -1
		}
		return 1
	case "integer":
		leftValue := left.(int64)
		rightValue := right.(int64)
		switch {
		case leftValue < rightValue:
			return -1
		case leftValue > rightValue:
			return 1
		default:
			return 0
		}
	case "string":
		leftValue := left.(string)
		rightValue := right.(string)
		switch {
		case leftValue < rightValue:
			return -1
		case leftValue > rightValue:
			return 1
		default:
			return 0
		}
	default:
		panic("unsupported scalar kind")
	}
}

func ValidateScalarSet(value any) error {
	values, err := scalarSetValues(value)
	if err != nil {
		return err
	}
	if len(values) < 1 || len(values) > 64 {
		return errors.New("values must contain between 1 and 64 entries")
	}

	normalized := make([]any, len(values))
	kind := ""
	for index, item := range values {
		itemKind, itemValue, err := scalarType(item)
		if err != nil {
			return err
		}
		if itemKind == "string" &&
			utf8.RuneCountInString(itemValue.(string)) >
				maxExpectedStringLength {
			return errors.New("values string exceeds maximum length")
		}
		if index == 0 {
			kind = itemKind
		} else if itemKind != kind {
			return errors.New(
				"values must contain one identical JSON scalar type",
			)
		}
		normalized[index] = itemValue
	}

	for index := 1; index < len(normalized); index++ {
		comparison := compareCanonicalScalars(
			kind,
			normalized[index-1],
			normalized[index],
		)
		if comparison == 0 {
			return errors.New("values must not contain duplicates")
		}
		if comparison > 0 {
			return errors.New("values must be in canonical order")
		}
	}
	return nil
}

func ValidateExpectedScalar(value any) error {
	kind, normalized, err := scalarType(value)
	if err != nil {
		return err
	}
	if kind == "string" &&
		utf8.RuneCountInString(normalized.(string)) > maxExpectedStringLength {
		return errors.New("expected string exceeds maximum length")
	}
	return nil
}

func observation(path string, resolution Resolution) map[string]any {
	var observedValue any
	if resolution.Status == "found" {
		switch resolution.ValueType {
		case "null", "boolean", "integer":
			observedValue = resolution.Value
		case "string":
			value, _ := resolution.Value.(string)
			if utf8.RuneCountInString(value) <= maxResultStringLength {
				observedValue = value
			}
		}
	}
	return map[string]any{
		"path":       path,
		"resolution": resolution.Status,
		"value_type": nullableString(resolution.ValueType),
		"value":      observedValue,
	}
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func strictScalarEqual(observed any, observedType string, expected any) bool {
	expectedType, normalizedExpected, err := scalarType(expected)
	if err != nil || observedType != expectedType {
		return false
	}
	switch observedType {
	case "integer":
		observedInteger, err := SafeInteger(observed, "observed")
		return err == nil && observedInteger == normalizedExpected.(int64)
	case "null":
		return observed == nil
	default:
		return reflect.DeepEqual(observed, normalizedExpected)
	}
}

func result(
	requirementID string,
	primitiveType string,
	satisfied bool,
	observed map[string]any,
	expected map[string]any,
	failureCode string,
) (map[string]any, string) {
	status := "satisfied"
	var failureValue any
	failure := ""
	if !satisfied {
		status = "unsatisfied"
		failure = failureCode
		failureValue = failureCode
	}
	return map[string]any{
		"requirement_id":  requirementID,
		"type":            primitiveType,
		"status":          status,
		"matched_signers": []string{},
		"observed":        observed,
		"expected":        expected,
		"failure_code":    failureValue,
	}, failure
}

func EvaluateValuePresent(
	requirement map[string]any,
	ctx model.Context,
) (map[string]any, string, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, "", err
	}
	path, err := parser.AsString(requirement["path"], "path")
	if err != nil {
		return nil, "", err
	}
	resolution, err := ResolvePath(ctx, path)
	if err != nil {
		return nil, "", err
	}
	output, failure := result(
		requirementID,
		TypeValuePresent,
		resolution.Status == "found",
		observation(path, resolution),
		map[string]any{"resolution": "found"},
		"CONTEXT_VALUE_NOT_PRESENT",
	)
	return output, failure, nil
}

func EvaluateValueEquals(
	requirement map[string]any,
	ctx model.Context,
) (map[string]any, string, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, "", err
	}
	path, err := parser.AsString(requirement["path"], "path")
	if err != nil {
		return nil, "", err
	}
	expectedValue := requirement["value"]
	resolution, err := ResolvePath(ctx, path)
	if err != nil {
		return nil, "", err
	}
	satisfied := resolution.Status == "found" &&
		strictScalarEqual(
			resolution.Value,
			resolution.ValueType,
			expectedValue,
		)
	output, failure := result(
		requirementID,
		TypeValueEquals,
		satisfied,
		observation(path, resolution),
		map[string]any{"value": expectedValue},
		"CONTEXT_VALUE_NOT_EQUAL",
	)
	return output, failure, nil
}

func EvaluateValueIn(
	requirement map[string]any,
	ctx model.Context,
) (map[string]any, string, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, "", err
	}
	path, err := parser.AsString(requirement["path"], "path")
	if err != nil {
		return nil, "", err
	}
	values, err := scalarSetValues(requirement["values"])
	if err != nil {
		return nil, "", err
	}
	resolution, err := ResolvePath(ctx, path)
	if err != nil {
		return nil, "", err
	}

	satisfied := false
	if resolution.Status == "found" {
		for _, expected := range values {
			if strictScalarEqual(
				resolution.Value,
				resolution.ValueType,
				expected,
			) {
				satisfied = true
				break
			}
		}
	}

	output, failure := result(
		requirementID,
		TypeValueIn,
		satisfied,
		observation(path, resolution),
		map[string]any{"values": requirement["values"]},
		"CONTEXT_VALUE_NOT_IN_SET",
	)
	return output, failure, nil
}

func EvaluatePathEquals(
	requirement map[string]any,
	ctx model.Context,
) (map[string]any, string, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, "", err
	}
	leftPath, err := parser.AsString(
		requirement["left_path"],
		"left_path",
	)
	if err != nil {
		return nil, "", err
	}
	rightPath, err := parser.AsString(
		requirement["right_path"],
		"right_path",
	)
	if err != nil {
		return nil, "", err
	}

	left, err := ResolvePath(ctx, leftPath)
	if err != nil {
		return nil, "", err
	}
	right, err := ResolvePath(ctx, rightPath)
	if err != nil {
		return nil, "", err
	}

	satisfied := left.Status == "found" &&
		right.Status == "found" &&
		strictScalarEqual(left.Value, left.ValueType, right.Value)

	output, failure := result(
		requirementID,
		TypePathEquals,
		satisfied,
		map[string]any{
			"left":  observation(leftPath, left),
			"right": observation(rightPath, right),
		},
		map[string]any{"relation": "strict_equal"},
		"CONTEXT_PATH_VALUES_NOT_EQUAL",
	)
	return output, failure, nil
}

func EvaluateIntegerAtLeast(
	requirement map[string]any,
	ctx model.Context,
) (map[string]any, string, error) {
	return evaluateIntegerBound(
		requirement,
		ctx,
		TypeIntegerLeast,
		"minimum",
		"CONTEXT_INTEGER_MINIMUM_NOT_REACHED",
		func(observed int64, expected int64) bool {
			return observed >= expected
		},
	)
}

func EvaluateIntegerAtMost(
	requirement map[string]any,
	ctx model.Context,
) (map[string]any, string, error) {
	return evaluateIntegerBound(
		requirement,
		ctx,
		TypeIntegerMost,
		"maximum",
		"CONTEXT_INTEGER_MAXIMUM_EXCEEDED",
		func(observed int64, expected int64) bool {
			return observed <= expected
		},
	)
}

func evaluateIntegerBound(
	requirement map[string]any,
	ctx model.Context,
	primitiveType string,
	boundField string,
	failureCode string,
	compare func(int64, int64) bool,
) (map[string]any, string, error) {
	requirementID, err := parser.AsString(
		requirement["requirement_id"],
		"requirement_id",
	)
	if err != nil {
		return nil, "", err
	}
	path, err := parser.AsString(requirement["path"], "path")
	if err != nil {
		return nil, "", err
	}
	bound, err := SafeInteger(requirement[boundField], boundField)
	if err != nil {
		return nil, "", err
	}
	resolution, err := ResolvePath(ctx, path)
	if err != nil {
		return nil, "", err
	}

	satisfied := false
	if resolution.Status == "found" &&
		resolution.ValueType == "integer" {
		observed, conversionErr := SafeInteger(
			resolution.Value,
			"observed",
		)
		satisfied = conversionErr == nil && compare(observed, bound)
	}

	output, failure := result(
		requirementID,
		primitiveType,
		satisfied,
		observation(path, resolution),
		map[string]any{boundField: bound},
		failureCode,
	)
	return output, failure, nil
}
