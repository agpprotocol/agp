package tpe

import (
	"encoding/json"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

func TestContextProposalProjectionPreservesJSONNumbers(t *testing.T) {
	raw := []byte(`{
		"object_type":"agp.decision-context/3",
		"context_id":"context:01",
		"policy":{
			"id":"policy:root",
			"version":1,
			"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"proposal":{
			"type":"proposal:change",
			"payload":{
				"limit":9007199254740991,
				"nested":{"enabled":true},
				"items":[1,"two",null]
			}
		},
		"participants":[],
		"evidence":[]
	}`)

	var public Context
	if err := parser.Decode(raw, &public); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	internal := toInternalContext(public)
	if internal.Proposal.Type != "proposal:change" {
		t.Fatalf("proposal type lost: %#v", internal.Proposal)
	}
	if _, ok := internal.Proposal.Payload["limit"].(json.Number); !ok {
		t.Fatalf(
			"integer token type lost: %T",
			internal.Proposal.Payload["limit"],
		)
	}

	public.Proposal.Payload["nested"].(map[string]any)["enabled"] = false
	if internal.Proposal.Payload["nested"].(map[string]any)["enabled"] != true {
		t.Fatal("public-to-internal payload was not detached")
	}
}
