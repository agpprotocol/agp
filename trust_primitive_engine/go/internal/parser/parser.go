package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Decode decodes exactly one JSON value and preserves integer tokens as
// json.Number. Trailing JSON values are rejected.
func Decode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing JSON data")
	}
	return nil
}

// DecodeFile loads and strictly decodes one JSON document.
func DecodeFile(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return Decode(raw, target)
}

// AsString returns value as a string.
func AsString(value any, field string) (string, error) {
	result, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", field)
	}
	return result, nil
}

// AsInt returns value as an integer.
func AsInt(value any, field string) (int, error) {
	switch typed := value.(type) {
	case json.Number:
		result, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", field)
		}
		return int(result), nil
	case float64:
		result := int(typed)
		if float64(result) != typed {
			return 0, fmt.Errorf("%s must be an integer", field)
		}
		return result, nil
	case int:
		return typed, nil
	default:
		return 0, fmt.Errorf("%s must be an integer", field)
	}
}

// AsStrings returns a detached string slice.
func AsStrings(value any, field string) ([]string, error) {
	raw, ok := value.([]any)
	if !ok {
		if typed, ok := value.([]string); ok {
			return append([]string(nil), typed...), nil
		}
		return nil, fmt.Errorf("%s must be an array", field)
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain strings", field)
		}
		result = append(result, text)
	}
	return result, nil
}
