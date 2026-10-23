package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const policyType = "manifold_governance_policy"

func policyServer(t *testing.T) (tfprotov6.ProviderServer, *tfprotov6.Schema, tftypes.Object) {
	t.Helper()
	srv, err := testAccProtoV6ProviderFactories["manifold"]()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.GetProviderSchema(t.Context(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	schema := resp.ResourceSchemas[policyType]
	typ, ok := schema.ValueType().(tftypes.Object)
	if !ok {
		t.Fatalf("%s schema type = %T, want an object", policyType, schema.ValueType())
	}
	return srv, schema, typ
}

func storedPolicyValues(typ tftypes.Object) map[string]tftypes.Value {
	str := func(s string) tftypes.Value { return tftypes.NewValue(tftypes.String, s) }
	return map[string]tftypes.Value{
		"id":           str("14636f3b-6a43-4f43-9a4e-5d3b0f6a6b0e"),
		"title":        str("conditional block"),
		"description":  str("before"),
		"category":     str("EXECUTION"),
		"action":       str("alert"),
		"cedar_policy": str("forbid(principal, action, resource);"),
		"severity":     str("medium"),
		"enabled":      tftypes.NewValue(tftypes.Bool, true),
		"priority":     tftypes.NewValue(tftypes.Number, 0),
		"action_options": tftypes.NewValue(typ.AttributeTypes["action_options"], map[string]tftypes.Value{
			"notify_user": tftypes.NewValue(tftypes.Bool, false),
		}),
		"taxonomy_mappings": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{}),
		"response_message":  tftypes.NewValue(tftypes.String, nil),
		"is_managed":        tftypes.NewValue(tftypes.Bool, false),
		"owner":             str("terraform"),
		"created_at":        str("2026-10-20T09:00:00Z"),
	}
}

func dynamicValue(t *testing.T, typ tftypes.Object, vals map[string]tftypes.Value) *tfprotov6.DynamicValue {
	t.Helper()
	dv, err := tfprotov6.NewDynamicValue(typ, tftypes.NewValue(typ, vals))
	if err != nil {
		t.Fatal(err)
	}
	return &dv
}

func TestUpdatePlansOnlyChangedAttributes(t *testing.T) {
	srv, schema, typ := policyServer(t)
	prior := storedPolicyValues(typ)

	proposed := storedPolicyValues(typ)
	proposed["action"] = tftypes.NewValue(tftypes.String, "block")

	config := storedPolicyValues(typ)
	config["action"] = proposed["action"]
	for _, a := range schema.Block.Attributes {
		if a.Computed && !a.Optional {
			config[a.Name] = tftypes.NewValue(typ.AttributeTypes[a.Name], nil)
		}
	}

	resp, err := srv.PlanResourceChange(t.Context(), &tfprotov6.PlanResourceChangeRequest{
		TypeName:         policyType,
		PriorState:       dynamicValue(t, typ, prior),
		ProposedNewState: dynamicValue(t, typ, proposed),
		Config:           dynamicValue(t, typ, config),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.Diagnostics {
		t.Fatalf("%s: %s", d.Summary, d.Detail)
	}

	planned, err := resp.PlannedState.Unmarshal(typ)
	if err != nil {
		t.Fatal(err)
	}
	if !planned.IsFullyKnown() {
		t.Errorf("planned state has unknown values: %s", planned)
	}
	if want := tftypes.NewValue(typ, proposed); !planned.Equal(want) {
		t.Errorf("planned state = %s, want %s", planned, want)
	}
}

func TestStateWithUpdatedAtStillLoads(t *testing.T) {
	srv, _, typ := policyServer(t)

	// State written by v0.1.x, whose resource schema still had updated_at.
	resp, err := srv.UpgradeResourceState(t.Context(), &tfprotov6.UpgradeResourceStateRequest{
		TypeName: policyType,
		Version:  0,
		RawState: &tfprotov6.RawState{JSON: []byte(`{
			"id": "14636f3b-6a43-4f43-9a4e-5d3b0f6a6b0e",
			"title": "conditional block",
			"description": "before",
			"category": "EXECUTION",
			"action": "alert",
			"cedar_policy": "forbid(principal, action, resource);",
			"severity": "medium",
			"enabled": true,
			"priority": 0,
			"action_options": {"notify_user": false},
			"taxonomy_mappings": [],
			"response_message": null,
			"is_managed": false,
			"owner": "terraform",
			"created_at": "2026-10-20T09:00:00Z",
			"updated_at": "2026-10-23T12:26:45.087674Z"
		}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.Diagnostics {
		t.Fatalf("%s: %s", d.Summary, d.Detail)
	}

	upgraded, err := resp.UpgradedState.Unmarshal(typ)
	if err != nil {
		t.Fatal(err)
	}
	if want := tftypes.NewValue(typ, storedPolicyValues(typ)); !upgraded.Equal(want) {
		t.Errorf("upgraded state = %s, want %s", upgraded, want)
	}
}
