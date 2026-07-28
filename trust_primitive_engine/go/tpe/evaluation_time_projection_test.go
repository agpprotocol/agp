package tpe

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

func TestEvaluationTimeProjectionPreservesAbsenceAndZero(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantNil  bool
		wantTime int64
	}{
		{
			name: "absent",
			raw: `{
				"object_type":"agp.decision-context/1",
				"context_id":"context:legacy",
				"policy":{
					"id":"policy:root",
					"version":1,
					"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				},
				"proposal":{"type":"proposal:test","payload":{}},
				"participants":[],
				"evidence":[]
			}`,
			wantNil: true,
		},
		{
			name: "zero",
			raw: `{
				"object_type":"agp.decision-context/2",
				"context_id":"context:zero",
				"evaluation_time":0,
				"policy":{
					"id":"policy:root",
					"version":1,
					"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				},
				"proposal":{"type":"proposal:test","payload":{}},
				"participants":[],
				"evidence":[]
			}`,
			wantTime: 0,
		},
		{
			name: "positive",
			raw: `{
				"object_type":"agp.decision-context/2",
				"context_id":"context:positive",
				"evaluation_time":1700000000,
				"policy":{
					"id":"policy:root",
					"version":1,
					"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				},
				"proposal":{"type":"proposal:test","payload":{}},
				"participants":[],
				"evidence":[]
			}`,
			wantTime: 1700000000,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var public Context
			if err := parser.Decode([]byte(test.raw), &public); err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			internal := toInternalContext(public)

			if test.wantNil {
				if public.EvaluationTime != nil ||
					internal.EvaluationTime != nil {
					t.Fatalf(
						"absence not preserved: public=%v internal=%v",
						public.EvaluationTime,
						internal.EvaluationTime,
					)
				}
				return
			}

			if public.EvaluationTime == nil ||
				internal.EvaluationTime == nil {
				t.Fatalf(
					"evaluation_time lost: public=%v internal=%v",
					public.EvaluationTime,
					internal.EvaluationTime,
				)
			}
			if *public.EvaluationTime != test.wantTime ||
				*internal.EvaluationTime != test.wantTime {
				t.Fatalf(
					"evaluation_time changed: public=%d internal=%d",
					*public.EvaluationTime,
					*internal.EvaluationTime,
				)
			}

			*public.EvaluationTime = test.wantTime + 1
			if *internal.EvaluationTime != test.wantTime {
				t.Fatal("evaluation_time pointer was not detached")
			}
		})
	}
}
