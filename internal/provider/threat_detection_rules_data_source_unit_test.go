package provider

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestRulesDataSourceWalksPages(t *testing.T) {
	h := newHarness(t)
	h.api.failWith("GET /threats/detection-rules", http.StatusTooManyRequests)

	state, diags := h.readData("manifold_threat_detection_rules", nil)
	h.noErrors(diags)
	if n := attrOf(t, state, "rules"); n != 3 {
		t.Fatalf("got %v rules across pages, want 3", n)
	}
	if got := attrOf(t, state, "rules", 2, "id"); got != "EXAMPLE-003" {
		t.Errorf("last rule id = %v", got)
	}
	// One throttled request, then two pages.
	if n := h.api.count("GET /threats/detection-rules"); n != 3 {
		t.Errorf("list sent %d times, want 3", n)
	}
}

func TestRulesDataSourceFilters(t *testing.T) {
	h := newHarness(t)
	h.api.rules["EXAMPLE-002"].Enabled = false

	ids := tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "EXAMPLE-001"),
		tftypes.NewValue(tftypes.String, "EXAMPLE-002"),
	})
	severities := tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "high"),
	})
	state, diags := h.readData("manifold_threat_detection_rules", map[string]any{
		"ids":        ids,
		"severities": severities,
		"enabled":    true,
		"query":      "example",
	})
	h.noErrors(diags)

	q := h.api.lastQuery
	if got := q["detection_rule_id"]; !slices.Equal(got, []string{"EXAMPLE-001", "EXAMPLE-002"}) {
		t.Errorf("detection_rule_id = %v", got)
	}
	if q.Get("severity") != "high" || q.Get("enabled") != "true" || q.Get("q") != "example" || q.Get("limit") != "250" {
		t.Errorf("query = %v", q)
	}
	if n := attrOf(t, state, "rules"); n != 1 {
		t.Fatalf("got %v rules, want only the enabled one", n)
	}
}

func TestRuleDataSource(t *testing.T) {
	h := newHarness(t)

	state, diags := h.readData("manifold_threat_detection_rule", map[string]any{"id": "EXAMPLE-001"})
	h.noErrors(diags)
	for name, want := range map[string]any{
		"title":            "Example rule 1",
		"severity":         "high",
		"what_it_detects":  "Example activity.",
		"potential_impact": "None.",
		"updated_at":       "2026-01-02T03:04:05Z",
	} {
		if got := attrOf(t, state, name); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}

	_, diags = h.readData("manifold_threat_detection_rule", map[string]any{"id": "EXAMPLE-404"})
	if msg := errorText(diags); !strings.Contains(msg, "HTTP 404") {
		t.Errorf("errors = %q, want a 404", msg)
	}
}
