package provider

import (
	"net/http"
	"strings"
	"testing"
)

const ruleType = "manifold_threat_detection_rule"

func TestRuleCreateAdoptsAndPatchesOnlyTheDiff(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}

	state, diags := h.create(map[string]any{"id": "EXAMPLE-001", "enabled": false, "severity": "high"})
	h.noErrors(diags)

	if n := len(h.api.patches); n != 1 {
		t.Fatalf("sent %d PATCHes, want 1", n)
	}
	p := h.api.patches[0]
	if p.ifMatch != `"v1"` {
		t.Errorf("If-Match = %q, want the ETag from the adopting read", p.ifMatch)
	}
	if len(p.body) != 1 || p.body["enabled"] != false {
		t.Errorf("body = %v, want only enabled=false", p.body)
	}
	if got := attrOf(t, state.value, "enabled"); got != false {
		t.Errorf("enabled = %v", got)
	}
	if got := attrOf(t, state.value, "title"); got != "Example rule 1" {
		t.Errorf("title = %v", got)
	}

	// The stored ETag is the one the PATCH returned, so the next update isn't refused as stale.
	updated, diags := h.apply(state, map[string]any{"id": "EXAMPLE-001", "enabled": false, "severity": "low"})
	h.noErrors(diags)
	if p := h.api.patches[1]; p.ifMatch != `"v2"` || len(p.body) != 1 || p.body["severity"] != "low" {
		t.Errorf("second PATCH = %+v, want only severity=low with If-Match \"v2\"", p)
	}
	if got := attrOf(t, updated.value, "severity"); got != "low" {
		t.Errorf("severity = %v", got)
	}
}

func TestRuleCreateWithoutTuningLeavesRuleAlone(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}

	state, diags := h.create(map[string]any{"id": "EXAMPLE-002"})
	h.noErrors(diags)
	if n := h.api.count("PATCH /threats/detection-rules/EXAMPLE-002"); n != 0 {
		t.Errorf("sent %d PATCHes, want none", n)
	}
	if got := attrOf(t, state.value, "severity"); got != "medium" {
		t.Errorf("severity = %v, want the rule's current value", got)
	}
	if got := attrOf(t, state.value, "enabled"); got != true {
		t.Errorf("enabled = %v, want the rule's current value", got)
	}

	// Dropping an attribute from config keeps the last value rather than planning a change.
	planned, _, resp := h.plan(state, map[string]any{"id": "EXAMPLE-002"})
	h.noErrors(resp.Diagnostics)
	if !planned.value.Equal(state.value) {
		t.Errorf("plan = %s, want no change from %s", planned.value, state.value)
	}
}

func TestRuleCreateUnknownID(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}

	_, diags := h.create(map[string]any{"id": "EXAMPLE-404", "enabled": false})
	if msg := errorText(diags); !strings.Contains(msg, "Detection rule not found") {
		t.Fatalf("errors = %q, want a not-found error", msg)
	}
}

func TestRuleCreateFailsClosedWithoutETag(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}
	h.api.noETag = true

	_, diags := h.create(map[string]any{"id": "EXAMPLE-001", "enabled": false})
	if msg := errorText(diags); !strings.Contains(msg, "Missing ETag") {
		t.Fatalf("errors = %q, want a missing ETag error", msg)
	}
	if n := len(h.api.patches); n != 0 {
		t.Errorf("sent %d PATCHes, want none", n)
	}
}

func TestRuleReadRemovesDeletedRule(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}
	state, diags := h.create(map[string]any{"id": "EXAMPLE-003"})
	h.noErrors(diags)

	delete(h.api.rules, "EXAMPLE-003")
	read, diags := h.read(state)
	h.noErrors(diags)
	if !read.value.IsNull() {
		t.Fatalf("state = %s, want it removed", read.value)
	}
}

func TestRuleReadShowsDriftAndRetries(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}
	state, diags := h.create(map[string]any{"id": "EXAMPLE-001", "severity": "high"})
	h.noErrors(diags)

	h.api.rules["EXAMPLE-001"].Severity = "critical"
	h.api.versions["EXAMPLE-001"]++
	h.api.failWith("GET /threats/detection-rules/EXAMPLE-001", http.StatusTooManyRequests, http.StatusServiceUnavailable)

	read, diags := h.read(state)
	h.noErrors(diags)
	if got := attrOf(t, read.value, "severity"); got != "critical" {
		t.Errorf("severity = %v, want the drifted value", got)
	}
	if n := h.api.count("GET /threats/detection-rules/EXAMPLE-001"); n != 4 {
		t.Errorf("GET sent %d times, want 4 (adopt, then 2 failures and a retry)", n)
	}

	planned, _, resp := h.plan(read, map[string]any{"id": "EXAMPLE-001", "severity": "high"})
	h.noErrors(resp.Diagnostics)
	if got := attrOf(t, planned.value, "severity"); got != "high" {
		t.Errorf("planned severity = %v, want the configured value back", got)
	}

	updated, diags := h.apply(read, map[string]any{"id": "EXAMPLE-001", "severity": "high"})
	h.noErrors(diags)
	if got := attrOf(t, updated.value, "severity"); got != "high" {
		t.Errorf("severity = %v", got)
	}
	if p := h.api.patches[len(h.api.patches)-1]; p.ifMatch != `"v2"` {
		t.Errorf("If-Match = %q, want the ETag from the refresh", p.ifMatch)
	}
}

func TestRuleUpdateRefusesStaleETag(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}
	state, diags := h.create(map[string]any{"id": "EXAMPLE-001"})
	h.noErrors(diags)

	h.api.versions["EXAMPLE-001"]++
	_, diags = h.apply(state, map[string]any{"id": "EXAMPLE-001", "enabled": false})
	if msg := errorText(diags); !strings.Contains(msg, "changed outside Terraform") {
		t.Fatalf("errors = %q, want a precondition failure", msg)
	}
	if !h.api.rules["EXAMPLE-001"].Enabled {
		t.Error("rule was disabled despite the stale ETag")
	}
}

func TestRuleUpdateFailsClosedWithoutETag(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}
	state, diags := h.create(map[string]any{"id": "EXAMPLE-001"})
	h.noErrors(diags)

	state.private = nil
	_, diags = h.apply(state, map[string]any{"id": "EXAMPLE-001", "enabled": false})
	if msg := errorText(diags); !strings.Contains(msg, "Missing ETag") {
		t.Fatalf("errors = %q, want a missing ETag error", msg)
	}
	if n := len(h.api.patches); n != 0 {
		t.Errorf("sent %d PATCHes, want none", n)
	}
}

func TestRuleUpdateIsNotRetried(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}
	state, diags := h.create(map[string]any{"id": "EXAMPLE-001"})
	h.noErrors(diags)

	h.api.failWith("PATCH /threats/detection-rules/EXAMPLE-001", http.StatusServiceUnavailable)
	_, diags = h.apply(state, map[string]any{"id": "EXAMPLE-001", "enabled": false})
	if msg := errorText(diags); !strings.Contains(msg, "HTTP 503") {
		t.Fatalf("errors = %q, want the 503", msg)
	}
	if n := h.api.count("PATCH /threats/detection-rules/EXAMPLE-001"); n != 1 {
		t.Errorf("PATCH sent %d times, want 1", n)
	}
}

func TestRuleDestroyLeavesRuleTuned(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}
	state, diags := h.create(map[string]any{"id": "EXAMPLE-001", "enabled": false})
	h.noErrors(diags)
	before := len(h.api.requests)

	gone, diags := h.apply(state, nil)
	h.noErrors(diags)
	if !gone.value.IsNull() {
		t.Errorf("state = %s, want null", gone.value)
	}
	if after := len(h.api.requests); after != before {
		t.Errorf("destroy made %v, want no API calls", h.api.requests[before:])
	}
	if h.api.rules["EXAMPLE-001"].Enabled {
		t.Error("destroy re-enabled the rule")
	}
}

func TestRuleImport(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}

	state, diags := h.importState("EXAMPLE-002")
	h.noErrors(diags)
	if got := attrOf(t, state.value, "severity"); got != "medium" {
		t.Errorf("severity = %v", got)
	}
	if _, diags := h.apply(state, map[string]any{"id": "EXAMPLE-002", "severity": "low"}); errorText(diags) != "" {
		t.Errorf("update after import: %s", errorText(diags))
	}

	missing, diags := h.importState("EXAMPLE-404")
	h.noErrors(diags)
	if !missing.value.IsNull() {
		t.Errorf("imported state = %s, want null so Terraform reports the rule missing", missing.value)
	}
}

func TestRuleChangingIDReplaces(t *testing.T) {
	h := resourceHarness{newHarness(t), ruleType}
	state, diags := h.create(map[string]any{"id": "EXAMPLE-001"})
	h.noErrors(diags)

	_, _, resp := h.plan(state, map[string]any{"id": "EXAMPLE-002"})
	h.noErrors(resp.Diagnostics)
	if len(resp.RequiresReplace) != 1 || resp.RequiresReplace[0].String() != `AttributeName("id")` {
		t.Errorf("RequiresReplace = %v, want id", resp.RequiresReplace)
	}
}
