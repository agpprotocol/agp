package model

// Policy is the validated internal representation of one Trust Policy 2
// document. Requirements retain their decoded JSON shape until the later
// typed-model migration phase.
type Policy struct {
	ObjectType    string           `json:"object_type"`
	PolicyID      string           `json:"policy_id"`
	Version       int              `json:"version"`
	EligibleRoles []string         `json:"eligible_roles"`
	Requirements  []map[string]any `json:"requirements"`
}
