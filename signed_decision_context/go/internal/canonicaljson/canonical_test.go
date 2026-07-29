package canonicaljson

import (
	"strings"
	"testing"
)

func TestBytesDeterministicObjectOrder(t *testing.T) {
	value := map[string]any{
		"z": int64(3),
		"a": "value",
		"m": true,
	}

	actual, err := Bytes(value)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	expected := `{"a":"value","m":true,"z":3}`
	if string(actual) != expected {
		t.Fatalf(
			"unexpected canonical JSON: %s",
			actual,
		)
	}
}

func TestBytesEscapesControlCharacters(t *testing.T) {
	actual, err := Bytes(
		map[string]any{
			"value": "\"\\\b\t\n\f\r\u0001",
		},
	)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	expected := `{"value":"\"\\\b\t\n\f\r\u0001"}`
	if string(actual) != expected {
		t.Fatalf(
			"unexpected escaped JSON: %s",
			actual,
		)
	}
}

func TestBytesRejectsUnsafeInteger(t *testing.T) {
	_, err := Bytes(int64(1 << 53))
	if err == nil {
		t.Fatal("unsafe integer unexpectedly accepted")
	}
	if err.Error() != "integer outside safe range" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBytesRejectsUnsupportedType(t *testing.T) {
	_, err := Bytes(float64(1))
	if err == nil {
		t.Fatal("float unexpectedly accepted")
	}
	if err.Error() != "unsupported type float64" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBytesRejectsExcessiveDepth(t *testing.T) {
	var value any = "leaf"

	for range 66 {
		value = []any{value}
	}

	_, err := Bytes(value)
	if err == nil {
		t.Fatal("excessive depth unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "maximum depth exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
}
