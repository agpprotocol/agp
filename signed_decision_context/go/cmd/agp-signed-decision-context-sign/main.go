package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agpprotocol.org/agp/signed-decision-context/sign"
	verifyapi "agpprotocol.org/agp/signed-decision-context/verify"
)

type arguments struct {
	inputPath   string
	privatePath string
	signerID    string
	keyID       string
	signatureID string
	signedAt    string
	outputPath  string
	schemaDir   string
	appendMode  bool
}

func usage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: agp-signed-decision-context-sign INPUT "+
			"--private-key FILE "+
			"--signer-id ID "+
			"--key-id ID "+
			"--signature-id ID "+
			"--signed-at TIMESTAMP "+
			"--output FILE "+
			"[--append] "+
			"[--schema-dir DIR]",
	)
}

func parseArguments(values []string) (arguments, error) {
	result := arguments{
		schemaDir: "registry/schemas",
	}

	for index := 0; index < len(values); index++ {
		current := values[index]

		switch current {
		case "--append":
			result.appendMode = true

		case "--private-key",
			"--signer-id",
			"--key-id",
			"--signature-id",
			"--signed-at",
			"--output",
			"--schema-dir":

			if index+1 >= len(values) {
				return arguments{}, fmt.Errorf(
					"missing value for %s",
					current,
				)
			}

			index++
			value := values[index]

			switch current {
			case "--private-key":
				result.privatePath = value
			case "--signer-id":
				result.signerID = value
			case "--key-id":
				result.keyID = value
			case "--signature-id":
				result.signatureID = value
			case "--signed-at":
				result.signedAt = value
			case "--output":
				result.outputPath = value
			case "--schema-dir":
				result.schemaDir = value
			}

		default:
			if strings.HasPrefix(current, "-") {
				return arguments{}, fmt.Errorf(
					"unknown option: %s",
					current,
				)
			}

			if result.inputPath != "" {
				return arguments{}, fmt.Errorf(
					"unexpected positional argument: %s",
					current,
				)
			}

			result.inputPath = current
		}
	}

	required := []struct {
		name  string
		value string
	}{
		{"input", result.inputPath},
		{"--private-key", result.privatePath},
		{"--signer-id", result.signerID},
		{"--key-id", result.keyID},
		{"--signature-id", result.signatureID},
		{"--signed-at", result.signedAt},
		{"--output", result.outputPath},
	}

	for _, item := range required {
		if item.value == "" {
			return arguments{}, fmt.Errorf(
				"missing required argument: %s",
				item.name,
			)
		}
	}

	return result, nil
}

func writeResult(path string, value any) error {
	encoded, err := sign.CanonicalBytes(value)
	if err != nil {
		return err
	}

	encoded = append(encoded, '\n')

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(
		parent,
		"."+filepath.Base(path)+".*.tmp",
	)
	if err != nil {
		return err
	}

	temporaryPath := temporary.Name()
	keep := false

	defer func() {
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()

	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}

	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}

	if err := temporary.Close(); err != nil {
		return err
	}

	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}

	keep = true
	return nil
}

func emit(value map[string]any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		fmt.Println(
			`{"status":"error","error_code":` +
				`"OUTPUT_WRITE_FAILED",` +
				`"detail":"unable to encode result"}`,
		)
		return
	}

	fmt.Println(string(encoded))
}

func signingFailure(err error) (string, string) {
	if code, ok := sign.ErrorCode(err); ok {
		return string(code), err.Error()
	}

	status, code, detail, ok := verifyapi.FailureDetails(err)
	if ok {
		_ = status
		return code, detail
	}

	return "SIGNING_FAILED", err.Error()
}

func run(values []string) int {
	args, err := parseArguments(values)
	if err != nil {
		usage()
		emit(map[string]any{
			"status":     "error",
			"error_code": "INVALID_ARGUMENTS",
			"detail":     err.Error(),
		})
		return 1
	}

	privateRaw, err := os.ReadFile(args.privatePath)
	if err != nil {
		emit(map[string]any{
			"status":     "error",
			"error_code": "PRIVATE_KEY_READ_FAILED",
			"detail":     err.Error(),
		})
		return 1
	}

	privateKey, err := sign.ParsePrivateKey(privateRaw)
	if err != nil {
		code, detail := signingFailure(err)
		emit(map[string]any{
			"status":     "error",
			"error_code": code,
			"detail":     detail,
		})
		return 1
	}

	input, err := verifyapi.LoadJSON(args.inputPath)
	if err != nil {
		code, detail := signingFailure(err)
		emit(map[string]any{
			"status":     "error",
			"error_code": code,
			"detail":     detail,
		})
		return 1
	}

	options := sign.Options{
		SignerID:    args.signerID,
		KeyID:       args.keyID,
		SignatureID: args.signatureID,
		SignedAt:    args.signedAt,
	}

	var result map[string]any

	if args.appendMode {
		result, err = sign.Append(
			input,
			privateKey,
			options,
		)
	} else {
		result, err = sign.Create(
			input,
			privateKey,
			options,
		)
	}

	if err != nil {
		code, detail := signingFailure(err)
		emit(map[string]any{
			"status":     "error",
			"error_code": code,
			"detail":     detail,
		})
		return 1
	}

	if err := writeResult(args.outputPath, result); err != nil {
		var typed *sign.Error
		detail := err.Error()

		if errors.As(err, &typed) {
			detail = typed.Detail
		}

		emit(map[string]any{
			"status":     "error",
			"error_code": "OUTPUT_WRITE_FAILED",
			"detail":     detail,
		})
		return 1
	}

	status := "signed"
	if args.appendMode {
		status = "signature_appended"
	}

	signatures, _ := result["signatures"].([]any)

	emit(map[string]any{
		"status":          status,
		"output":          args.outputPath,
		"signature_id":    args.signatureID,
		"signature_count": len(signatures),
	})

	return 0
}

func main() {
	os.Exit(run(os.Args[1:]))
}
