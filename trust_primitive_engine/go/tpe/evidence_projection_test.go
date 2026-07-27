package tpe

import (
	"encoding/json"
	"testing"
)

func TestEvidenceProjectionPreservesManifestFields(t *testing.T) {
	raw := []byte(`{
		"object_type":"agp.decision-context/3",
		"context_id":"context:01",
		"policy":{
			"id":"policy:root",
			"version":1,
			"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"participants":[],
		"evidence":[{
			"id":"evidence:01",
			"digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"media_type":"application/json",
			"evidence_type":"agp.evidence.security-review/1",
			"issuer_id":"authority:security"
		}]
	}`)

	var public Context
	if err := json.Unmarshal(raw, &public); err != nil {
		t.Fatalf("decode public context: %v", err)
	}
	if len(public.Evidence) != 1 {
		t.Fatalf("unexpected evidence: %#v", public.Evidence)
	}

	item := public.Evidence[0]
	if item.Digest != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("digest was not preserved: %#v", item)
	}
	if item.MediaType != "application/json" {
		t.Fatalf("media type was not preserved: %#v", item)
	}

	internal := toInternalContext(public)
	if len(internal.Evidence) != 1 {
		t.Fatalf("unexpected internal evidence: %#v", internal.Evidence)
	}
	internalItem := internal.Evidence[0]
	if internalItem.Digest != item.Digest ||
		internalItem.MediaType != item.MediaType ||
		internalItem.EvidenceType != item.EvidenceType ||
		internalItem.IssuerID != item.IssuerID {
		t.Fatalf(
			"public-to-internal projection lost manifest fields: public=%#v internal=%#v",
			item,
			internalItem,
		)
	}
}

func TestEvidenceProjectionJSONRoundTrip(t *testing.T) {
	original := Context{
		ObjectType: "agp.decision-context/3",
		ContextID:  "context:01",
		Evidence: []Evidence{
			{
				ID:           "evidence:01",
				Digest:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				MediaType:    "application/pdf",
				EvidenceType: "agp.evidence.quote/1",
				IssuerID:     "authority:procurement",
			},
		},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("encode context: %v", err)
	}

	var decoded Context
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode context: %v", err)
	}
	if len(decoded.Evidence) != 1 {
		t.Fatalf("unexpected evidence: %#v", decoded.Evidence)
	}
	if decoded.Evidence[0] != original.Evidence[0] {
		t.Fatalf(
			"evidence round trip changed fields: got=%#v want=%#v",
			decoded.Evidence[0],
			original.Evidence[0],
		)
	}
}
