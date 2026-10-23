package provider

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

func storedPolicy(t *testing.T) governancePolicyDetailModel {
	t.Helper()
	cedar := `forbid(principal, action, resource is Tool);`
	msg := "Blocked."
	m, diags := newGovernancePolicyDetailModel(t.Context(), client.GovernancePolicy{
		PolicyId:         uuid.New(),
		Title:            "legacy",
		Description:      "before",
		Category:         "EXECUTION",
		Severity:         "high",
		Action:           "block",
		CedarPolicy:      &cedar,
		Enabled:          true,
		TaxonomyMappings: []string{"OWASP-ASI02"},
		ResponseMessage:  &msg,
	})
	if diags.HasError() {
		t.Fatal(diags)
	}
	return m
}

func patchBody(t *testing.T, plan, state governancePolicyDetailModel) map[string]any {
	t.Helper()
	u, diags := changedFields(t.Context(), plan, state)
	if diags.HasError() {
		t.Fatal(diags)
	}
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestChangedFieldsSendsOnlyTheDiff(t *testing.T) {
	state := storedPolicy(t)
	plan := state
	plan.Description = types.StringValue("after")

	body := patchBody(t, plan, state)
	if len(body) != 1 || body["description"] != "after" {
		t.Fatalf("body = %v, want only description", body)
	}
}

func TestChangedFieldsClearsResponseMessage(t *testing.T) {
	state := storedPolicy(t)
	plan := state
	plan.ResponseMessage = types.StringNull()

	body := patchBody(t, plan, state)
	if msg, ok := body["response_message"]; len(body) != 1 || !ok || msg != "" {
		t.Fatalf("body = %v, want only an empty response_message", body)
	}
}

func TestChangedFieldsEmptyWithoutChanges(t *testing.T) {
	state := storedPolicy(t)
	if body := patchBody(t, state, state); len(body) != 0 {
		t.Fatalf("body = %v, want empty", body)
	}
}
