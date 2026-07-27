package model

import "testing"

func validIdentity(t *testing.T) PolicyIdentity {
	t.Helper()
	identity, err := NewPolicyIdentity(
		"policy:example",
		1,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	return identity
}

func TestPolicyIdentityValidation(t *testing.T) {
	if _, err := NewPolicyIdentity("", 1, "a"); err == nil {
		t.Fatal("empty policy id accepted")
	}
	if _, err := NewPolicyIdentity("policy:example", 0, "a"); err == nil {
		t.Fatal("zero policy version accepted")
	}
	if _, err := NewPolicyIdentity(
		"policy:example",
		1,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	); err == nil {
		t.Fatal("uppercase digest accepted")
	}
}

func TestRequirementResultInvariants(t *testing.T) {
	valid := RequirementResult{
		RequirementID:  "requirement:01",
		Type:           "required_signer",
		Status:         StatusSatisfied,
		MatchedSigners: []string{"authority:a", "authority:b"},
		Observed:       map[string]any{},
		Expected:       map[string]any{},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	invalid := valid
	invalid.FailureCode = "SHOULD_NOT_EXIST"
	if err := invalid.Validate(); err == nil {
		t.Fatal("satisfied result with failure code accepted")
	}
	invalid = valid
	invalid.MatchedSigners = []string{"authority:b", "authority:a"}
	if err := invalid.Validate(); err == nil {
		t.Fatal("unsorted matched signers accepted")
	}
}

func TestPolicyResultInvariants(t *testing.T) {
	unsatisfied := PolicyResult{
		Identity:       validIdentity(t),
		Status:         StatusUnsatisfied,
		MatchedSigners: []string{"authority:a"},
		FailureCodes:   []string{"REQUIRED_SIGNER_MISSING"},
	}
	if err := unsatisfied.Validate(); err != nil {
		t.Fatalf("valid unsatisfied policy rejected: %v", err)
	}
	unsatisfied.FailureCodes = nil
	if err := unsatisfied.Validate(); err == nil {
		t.Fatal("unsatisfied policy without failures accepted")
	}
}
