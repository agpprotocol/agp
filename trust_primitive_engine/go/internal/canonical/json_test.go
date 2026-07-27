package canonical

import "testing"

func TestBytesSortedCompactAndUnescaped(t *testing.T) {
	value := map[string]any{
		"z": "<value>",
		"a": []any{true, int64(2), "é"},
	}
	got, err := Bytes(value)
	if err != nil {
		t.Fatalf("canonical encoding failed: %v", err)
	}
	const expected = `{"a":[true,2,"é"],"z":"<value>"}`
	if string(got) != expected {
		t.Fatalf("unexpected canonical bytes: got %s want %s", got, expected)
	}
}

func TestSHA256DeterministicAcrossMapInsertionOrder(t *testing.T) {
	left := map[string]any{"b": int64(2), "a": int64(1)}
	right := map[string]any{"a": int64(1), "b": int64(2)}

	leftDigest, err := SHA256(left)
	if err != nil {
		t.Fatalf("left digest failed: %v", err)
	}
	rightDigest, err := SHA256(right)
	if err != nil {
		t.Fatalf("right digest failed: %v", err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("digests differ: left=%s right=%s", leftDigest, rightDigest)
	}
	const expected = "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
	if leftDigest != expected {
		t.Fatalf("unexpected digest: got %s want %s", leftDigest, expected)
	}
}

func TestBytesRejectsUnsupportedValue(t *testing.T) {
	if _, err := Bytes(make(chan int)); err == nil {
		t.Fatal("unsupported value unexpectedly encoded")
	}
}
