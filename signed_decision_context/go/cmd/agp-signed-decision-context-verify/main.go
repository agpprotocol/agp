package main

import (
	"encoding/json"
	"fmt"
	"os"

	verifyapi "agpprotocol.org/agp/signed-decision-context/verify"
)

type arguments struct {
	input          string
	keyring        string
	schemaDir      string
	structuralOnly bool
}

func parseArguments(raw []string) (*arguments, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf(
			"usage: agp-signed-decision-context-verify " +
				"INPUT.json (--structural-only | " +
				"--keyring KEYRING.json) [--schema-dir DIR]",
		)
	}

	result := &arguments{input: raw[0]}

	for index := 1; index < len(raw); index++ {
		switch raw[index] {
		case "--keyring":
			index++
			if index >= len(raw) {
				return nil, fmt.Errorf("--keyring requires a path")
			}
			result.keyring = raw[index]

		case "--schema-dir":
			index++
			if index >= len(raw) {
				return nil, fmt.Errorf("--schema-dir requires a path")
			}
			result.schemaDir = raw[index]

		case "--structural-only":
			result.structuralOnly = true

		default:
			return nil, fmt.Errorf("unknown argument: %s", raw[index])
		}
	}

	if result.structuralOnly && result.keyring != "" {
		return nil, fmt.Errorf(
			"--structural-only and --keyring are mutually exclusive",
		)
	}
	if !result.structuralOnly && result.keyring == "" {
		return nil, fmt.Errorf(
			"--keyring is required unless --structural-only is used",
		)
	}
	return result, nil
}

func writeResult(value map[string]any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func main() {
	args, err := parseArguments(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	value, err := verifyapi.LoadJSON(args.input)

	if err == nil && args.structuralOnly {
		var structural verifyapi.StructuralResult
		structural, err = verifyapi.StructuralValidate(value)
		if err == nil {
			writeResult(map[string]any{
				"status":          "valid",
				"object_type":     structural.ObjectType,
				"context_digest":  structural.ContextDigest,
				"signature_count": structural.SignatureCount,
			})
			return
		}
	}

	if err == nil && !args.structuralOnly {
		var keyring verifyapi.Keyring
		keyring, err = verifyapi.LoadKeyring(args.keyring)
		if err == nil {
			var result map[string]any
			result, err = verifyapi.Verify(value, keyring)
			if err == nil {
				writeResult(result)
				return
			}
		}
	}

	if status, code, detail, ok := verifyapi.FailureDetails(err); ok {
		writeResult(map[string]any{
			"status":     status,
			"error_code": code,
			"detail":     detail,
		})
		os.Exit(1)
	}

	writeResult(map[string]any{
		"status":     "unverified",
		"error_code": "INTERNAL_ERROR",
		"detail":     err.Error(),
	})
	os.Exit(1)
}
