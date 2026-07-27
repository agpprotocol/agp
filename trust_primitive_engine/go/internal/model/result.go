package model

import (
	"fmt"
	"slices"
)

type Status string

const (
	StatusSatisfied   Status = "satisfied"
	StatusUnsatisfied Status = "unsatisfied"
)

type RequirementResult struct {
	RequirementID    string
	Type             string
	Status           Status
	MatchedSigners   []string
	Observed         map[string]any
	Expected         map[string]any
	FailureCode      string
	Children         []RequirementResult
	ReferencedPolicy *PolicyResult
}

type PolicyResult struct {
	Identity           PolicyIdentity
	Status             Status
	RequirementResults []RequirementResult
	MatchedSigners     []string
	FailureCodes       []string
}

func (r RequirementResult) Validate() error {
	if r.RequirementID == "" {
		return fmt.Errorf("requirement id must not be empty")
	}
	if r.Type == "" {
		return fmt.Errorf("requirement type must not be empty")
	}
	if err := validateStatusFailure(r.Status, r.FailureCode); err != nil {
		return err
	}
	if !sortedUnique(r.MatchedSigners) {
		return fmt.Errorf("matched signers must be sorted and unique")
	}
	for index := range r.Children {
		if err := r.Children[index].Validate(); err != nil {
			return fmt.Errorf("child[%d]: %w", index, err)
		}
	}
	if r.ReferencedPolicy != nil {
		if err := r.ReferencedPolicy.Validate(); err != nil {
			return fmt.Errorf("referenced policy: %w", err)
		}
	}
	return nil
}

func (r PolicyResult) Validate() error {
	if r.Identity.ID == "" {
		return fmt.Errorf("policy identity is required")
	}
	if r.Status != StatusSatisfied && r.Status != StatusUnsatisfied {
		return fmt.Errorf("invalid policy status: %q", r.Status)
	}
	if !sortedUnique(r.MatchedSigners) {
		return fmt.Errorf("matched signers must be sorted and unique")
	}
	for index := range r.RequirementResults {
		if err := r.RequirementResults[index].Validate(); err != nil {
			return fmt.Errorf("requirement[%d]: %w", index, err)
		}
	}
	if r.Status == StatusSatisfied && len(r.FailureCodes) != 0 {
		return fmt.Errorf("satisfied policy must not contain failure codes")
	}
	if r.Status == StatusUnsatisfied && len(r.FailureCodes) == 0 {
		return fmt.Errorf("unsatisfied policy must contain failure codes")
	}
	for _, code := range r.FailureCodes {
		if code == "" {
			return fmt.Errorf("failure codes must not contain empty values")
		}
	}
	return nil
}

func validateStatusFailure(status Status, failureCode string) error {
	switch status {
	case StatusSatisfied:
		if failureCode != "" {
			return fmt.Errorf("satisfied result must not contain a failure code")
		}
	case StatusUnsatisfied:
		if failureCode == "" {
			return fmt.Errorf("unsatisfied result must contain a failure code")
		}
	default:
		return fmt.Errorf("invalid result status: %q", status)
	}
	return nil
}

func sortedUnique(values []string) bool {
	if !slices.IsSorted(values) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return false
		}
	}
	return true
}
