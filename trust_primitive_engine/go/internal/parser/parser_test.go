package parser

import (
	"encoding/json"
	"testing"
)

func TestDecodeUsesNumberAndRejectsTrailingData(t *testing.T) {
	var value map[string]any
	if err := Decode([]byte(`{"value":9007199254740991}`), &value); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	if _, ok := value["value"].(json.Number); !ok {
		t.Fatalf("number type = %T, want json.Number", value["value"])
	}

	if err := Decode([]byte(`{} {}`), &value); err == nil {
		t.Fatal("trailing JSON data accepted")
	}
}

func TestConversionHelpers(t *testing.T) {
	if got, err := AsString("value", "field"); err != nil || got != "value" {
		t.Fatalf("AsString: got=%q err=%v", got, err)
	}
	if got, err := AsInt(json.Number("7"), "field"); err != nil || got != 7 {
		t.Fatalf("AsInt: got=%d err=%v", got, err)
	}
	values, err := AsStrings([]any{"a", "b"}, "field")
	if err != nil || len(values) != 2 {
		t.Fatalf("AsStrings: values=%v err=%v", values, err)
	}
}
