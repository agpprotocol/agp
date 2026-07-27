package model

import (
	"fmt"
	"regexp"
)

var lowercaseSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PolicyIdentity identifies one immutable Trust Policy document.
type PolicyIdentity struct {
	ID      string
	Version int64
	Digest  string
}

func NewPolicyIdentity(id string, version int64, digest string) (PolicyIdentity, error) {
	switch {
	case id == "":
		return PolicyIdentity{}, fmt.Errorf("policy id must not be empty")
	case version < 1:
		return PolicyIdentity{}, fmt.Errorf("policy version must be positive")
	case !lowercaseSHA256.MatchString(digest):
		return PolicyIdentity{}, fmt.Errorf(
			"policy digest must be 64 lowercase hexadecimal characters",
		)
	default:
		return PolicyIdentity{ID: id, Version: version, Digest: digest}, nil
	}
}
