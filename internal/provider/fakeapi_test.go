package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

const fakePageSize = 2

type fakePatch struct {
	ifMatch string
	body    map[string]any
}

// fakeAPI is an in-memory management API for exercising the provider over the plugin protocol.
type fakeAPI struct {
	*httptest.Server
	mu       sync.Mutex
	rules    map[string]*client.ThreatDetectionRule
	versions map[string]int
	noETag   bool
	// failNext holds statuses served, in order, before "METHOD /path" reaches its handler.
	failNext  map[string][]int
	groups    []client.CustomDeviceGroup
	requests  []string
	patches   []fakePatch
	lastQuery url.Values
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f := &fakeAPI{
		rules:    map[string]*client.ThreatDetectionRule{},
		versions: map[string]int{},
		failNext: map[string][]int{},
	}
	for i, sev := range []string{"high", "medium", "low"} {
		id := fmt.Sprintf("EXAMPLE-%03d", i+1)
		f.rules[id] = &client.ThreatDetectionRule{
			DetectionRuleId:  id,
			Title:            "Example rule " + strconv.Itoa(i+1),
			Description:      "An example detection.",
			Category:         "EXAMPLE",
			Severity:         sev,
			Enabled:          true,
			Owner:            "manifold",
			TaxonomyMappings: []string{"EXAMPLE-TAXONOMY"},
			CreatedAt:        created,
			UpdatedAt:        created,
			WhatItDetects:    "Example activity.",
			WhyItMatters:     "It is an example.",
			PotentialImpact:  "None.",
		}
		f.versions[id] = 1
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":900}`))
	})
	api := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			key := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/api/management/v1")
			f.requests = append(f.requests, key)
			if q := f.failNext[key]; len(q) > 0 {
				f.failNext[key] = q[1:]
				w.Header().Set("Retry-After", "0")
				problem(w, q[0])
				return
			}
			h(w, r)
		})
	}

	api("GET /api/management/v1/threats/detection-rules", f.listRules)
	api("GET /api/management/v1/threats/detection-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		rule, ok := f.rules[r.PathValue("id")]
		if !ok {
			problem(w, http.StatusNotFound)
			return
		}
		f.writeRule(w, rule)
	})
	api("PATCH /api/management/v1/threats/detection-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		rule, ok := f.rules[id]
		if !ok {
			problem(w, http.StatusNotFound)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) == 0 {
			problem(w, http.StatusBadRequest)
			return
		}
		ifMatch := r.Header.Get("If-Match")
		f.patches = append(f.patches, fakePatch{ifMatch: ifMatch, body: body})
		if ifMatch != "" && ifMatch != f.etag(id) {
			problem(w, http.StatusPreconditionFailed)
			return
		}
		if v, ok := body["enabled"].(bool); ok {
			rule.Enabled = v
		}
		if v, ok := body["severity"].(string); ok {
			rule.Severity = v
		}
		f.versions[id]++
		f.writeRule(w, rule)
	})

	api("GET /api/management/v1/devices/groups", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(client.CustomDeviceGroupList{Groups: f.groups})
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPI) etag(id string) string {
	return fmt.Sprintf(`"v%d"`, f.versions[id])
}

func (f *fakeAPI) writeRule(w http.ResponseWriter, rule *client.ThreatDetectionRule) {
	if !f.noETag {
		w.Header().Set("ETag", f.etag(rule.DetectionRuleId))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rule)
}

func (f *fakeAPI) listRules(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.lastQuery = q
	ids := make([]string, 0, len(f.rules))
	for id, rule := range f.rules {
		if want := q["detection_rule_id"]; len(want) > 0 && !slices.Contains(want, id) {
			continue
		}
		if want := q.Get("enabled"); want != "" && want != strconv.FormatBool(rule.Enabled) {
			continue
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)

	start, _ := strconv.Atoi(q.Get("cursor"))
	end := min(start+fakePageSize, len(ids))
	page := client.ThreatDetectionRuleList{Data: []client.ThreatDetectionRuleSummary{}}
	for _, id := range ids[start:end] {
		page.Data = append(page.Data, ruleSummary(*f.rules[id]))
	}
	if end < len(ids) {
		next := strconv.Itoa(end)
		page.HasNext, page.NextCursor = true, &next
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page)
}

func problem(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"type":"about:blank","title":%q,"status":%d}`, http.StatusText(status), status)
}

func (f *fakeAPI) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == key {
			n++
		}
	}
	return n
}

func (f *fakeAPI) failWith(key string, statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[key] = append(f.failNext[key], statuses...)
}

// harness drives a configured provider over the plugin protocol, as Terraform would.
type harness struct {
	t       *testing.T
	api     *fakeAPI
	srv     tfprotov6.ProviderServer
	schemas *tfprotov6.GetProviderSchemaResponse
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	f := newFakeAPI(t)
	srv, err := providerserver.NewProtocol6WithError(&manifoldProvider{version: "test", tokenURL: f.URL + "/oauth/token"})()
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := srv.GetProviderSchema(t.Context(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, api: f, srv: srv, schemas: schemas}

	cfg := h.value(schemas.Provider, map[string]any{
		"endpoint":      f.URL,
		"client_id":     "cid",
		"client_secret": "secret",
		"organization":  "org_test",
	})
	resp, err := srv.ConfigureProvider(t.Context(), &tfprotov6.ConfigureProviderRequest{Config: h.dynamic(cfg)})
	if err != nil {
		t.Fatal(err)
	}
	h.noErrors(resp.Diagnostics)
	return h
}

func (h *harness) value(s *tfprotov6.Schema, vals map[string]any) tftypes.Value {
	h.t.Helper()
	typ, ok := s.ValueType().(tftypes.Object)
	if !ok {
		h.t.Fatalf("schema type = %T, want an object", s.ValueType())
	}
	out := map[string]tftypes.Value{}
	for name, at := range typ.AttributeTypes {
		switch v := vals[name].(type) {
		case nil:
			out[name] = tftypes.NewValue(at, nil)
		case tftypes.Value:
			out[name] = v
		case []string:
			elems := make([]tftypes.Value, len(v))
			for i, e := range v {
				elems[i] = tftypes.NewValue(tftypes.String, e)
			}
			out[name] = tftypes.NewValue(at, elems)
		default:
			out[name] = tftypes.NewValue(at, v)
		}
	}
	return tftypes.NewValue(typ, out)
}

func (h *harness) dynamic(v tftypes.Value) *tfprotov6.DynamicValue {
	h.t.Helper()
	dv, err := tfprotov6.NewDynamicValue(v.Type(), v)
	if err != nil {
		h.t.Fatal(err)
	}
	return &dv
}

func (h *harness) decode(s *tfprotov6.Schema, dv *tfprotov6.DynamicValue) tftypes.Value {
	h.t.Helper()
	v, err := dv.Unmarshal(s.ValueType())
	if err != nil {
		h.t.Fatal(err)
	}
	return v
}

func (h *harness) noErrors(diags []*tfprotov6.Diagnostic) {
	h.t.Helper()
	if msg := errorText(diags); msg != "" {
		h.t.Fatal(msg)
	}
}

func errorText(diags []*tfprotov6.Diagnostic) string {
	var msgs []string
	for _, d := range diags {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			msgs = append(msgs, d.Summary+": "+d.Detail)
		}
	}
	return strings.Join(msgs, "\n")
}

// resourceHarness drives one resource type.
type resourceHarness struct {
	*harness
	typeName string
}

func (h resourceHarness) create(config map[string]any) (resourceState, []*tfprotov6.Diagnostic) {
	h.t.Helper()
	return h.apply(h.null(), config)
}

type resourceState struct {
	value   tftypes.Value
	private []byte
}

// plan proposes config over prior the way Terraform core does for top-level attributes.
func (h resourceHarness) plan(prior resourceState, config map[string]any) (resourceState, tftypes.Value, *tfprotov6.PlanResourceChangeResponse) {
	h.t.Helper()
	s := h.schemas.ResourceSchemas[h.typeName]
	cfg := h.value(s, config)

	var priorVals map[string]tftypes.Value
	if !prior.value.IsNull() {
		if err := prior.value.As(&priorVals); err != nil {
			h.t.Fatal(err)
		}
	}
	proposed := map[string]any{}
	for _, a := range s.Block.Attributes {
		v, ok := config[a.Name]
		if (!ok || v == nil) && a.Computed && priorVals != nil {
			v = priorVals[a.Name]
		}
		proposed[a.Name] = v
	}

	resp, err := h.srv.PlanResourceChange(h.t.Context(), &tfprotov6.PlanResourceChangeRequest{
		TypeName:         h.typeName,
		PriorState:       h.dynamic(prior.value),
		ProposedNewState: h.dynamic(h.value(s, proposed)),
		Config:           h.dynamic(cfg),
		PriorPrivate:     prior.private,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if errorText(resp.Diagnostics) != "" {
		return resourceState{}, cfg, resp
	}
	return resourceState{h.decode(s, resp.PlannedState), resp.PlannedPrivate}, cfg, resp
}

// apply plans and applies config over prior; a nil config destroys.
func (h resourceHarness) apply(prior resourceState, config map[string]any) (resourceState, []*tfprotov6.Diagnostic) {
	h.t.Helper()
	s := h.schemas.ResourceSchemas[h.typeName]
	planned, cfg := resourceState{value: tftypes.NewValue(s.ValueType(), nil), private: prior.private}, tftypes.NewValue(s.ValueType(), nil)
	if config != nil {
		var resp *tfprotov6.PlanResourceChangeResponse
		planned, cfg, resp = h.plan(prior, config)
		if errorText(resp.Diagnostics) != "" {
			return resourceState{}, resp.Diagnostics
		}
	}
	resp, err := h.srv.ApplyResourceChange(h.t.Context(), &tfprotov6.ApplyResourceChangeRequest{
		TypeName:       h.typeName,
		PriorState:     h.dynamic(prior.value),
		PlannedState:   h.dynamic(planned.value),
		Config:         h.dynamic(cfg),
		PlannedPrivate: planned.private,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return resourceState{h.decode(s, resp.NewState), resp.Private}, resp.Diagnostics
}

func (h resourceHarness) null() resourceState {
	return resourceState{value: tftypes.NewValue(h.schemas.ResourceSchemas[h.typeName].ValueType(), nil)}
}

func (h resourceHarness) read(state resourceState) (resourceState, []*tfprotov6.Diagnostic) {
	h.t.Helper()
	s := h.schemas.ResourceSchemas[h.typeName]
	resp, err := h.srv.ReadResource(h.t.Context(), &tfprotov6.ReadResourceRequest{
		TypeName:     h.typeName,
		CurrentState: h.dynamic(state.value),
		Private:      state.private,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return resourceState{h.decode(s, resp.NewState), resp.Private}, resp.Diagnostics
}

func (h resourceHarness) importState(id string) (resourceState, []*tfprotov6.Diagnostic) {
	h.t.Helper()
	s := h.schemas.ResourceSchemas[h.typeName]
	resp, err := h.srv.ImportResourceState(h.t.Context(), &tfprotov6.ImportResourceStateRequest{TypeName: h.typeName, ID: id})
	if err != nil {
		h.t.Fatal(err)
	}
	if len(resp.ImportedResources) != 1 {
		return resourceState{}, resp.Diagnostics
	}
	imported := resp.ImportedResources[0]
	return h.read(resourceState{h.decode(s, imported.State), imported.Private})
}

func (h *harness) readData(typeName string, config map[string]any) (tftypes.Value, []*tfprotov6.Diagnostic) {
	h.t.Helper()
	s := h.schemas.DataSourceSchemas[typeName]
	resp, err := h.srv.ReadDataSource(h.t.Context(), &tfprotov6.ReadDataSourceRequest{
		TypeName: typeName,
		Config:   h.dynamic(h.value(s, config)),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if errorText(resp.Diagnostics) != "" {
		return tftypes.Value{}, resp.Diagnostics
	}
	return h.decode(s, resp.State), resp.Diagnostics
}

// attrOf walks attribute names and list indexes to a string, bool or nil; a list comes back as its length.
func attrOf(t *testing.T, v tftypes.Value, steps ...any) any {
	t.Helper()
	for _, step := range steps {
		switch s := step.(type) {
		case string:
			var m map[string]tftypes.Value
			if err := v.As(&m); err != nil {
				t.Fatal(err)
			}
			v = m[s]
		case int:
			var l []tftypes.Value
			if err := v.As(&l); err != nil {
				t.Fatal(err)
			}
			if s >= len(l) {
				t.Fatalf("index %d out of range for %d elements", s, len(l))
			}
			v = l[s]
		}
	}
	if v.IsNull() {
		return nil
	}
	switch {
	case v.Type().Is(tftypes.String):
		var s string
		_ = v.As(&s)
		return s
	case v.Type().Is(tftypes.Bool):
		var b bool
		_ = v.As(&b)
		return b
	case v.Type().Is(tftypes.List{}):
		var l []tftypes.Value
		_ = v.As(&l)
		return len(l)
	}
	return v
}
