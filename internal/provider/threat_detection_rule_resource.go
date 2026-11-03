package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

var (
	_ resource.ResourceWithConfigure   = &threatDetectionRuleResource{}
	_ resource.ResourceWithImportState = &threatDetectionRuleResource{}
	_ resource.ResourceWithModifyPlan  = &threatDetectionRuleResource{}
)

type threatDetectionRuleResource struct {
	client *client.Manifold
}

func NewThreatDetectionRuleResource() resource.Resource {
	return &threatDetectionRuleResource{}
}

func (r *threatDetectionRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_detection_rule"
}

func (r *threatDetectionRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Tunes one of Manifold's built-in threat detection rules. Rules can't be created or deleted, so this resource adopts an existing rule by id and manages only the attributes you set: `enabled` and `severity`. Leaving one out leaves it as it is.\n\n" +
			"Destroying the resource only removes it from state; the rule keeps its last tuning, because the API doesn't expose a rule's default settings to reset it to. Set the values you want back before destroying if that matters.\n\n" +
			"A rule's id can stop existing when Manifold renames or retires the rule. Refresh then drops it from state with a warning, and the plan fails rather than proposing a create that can't succeed: set `id` to the rule's current id from `manifold_threat_detection_rules`, or remove the resource.\n\n" +
			"Updates send the `ETag` from the last refresh as `If-Match`, so a rule retuned elsewhere after the plan was made fails the apply instead of being overwritten. Needs the `read:threats` and `write:threats` scopes.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The rule's identifier, as listed by `manifold_threat_detection_rules`. Changing it adopts a different rule.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the rule runs. Switching it off stops new threats; those it already raised stay.",
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"severity": schema.StringAttribute{
				MarkdownDescription: "Severity the rule's threats carry: `critical`, `high`, `medium` or `low`. A retune also applies to threats the rule already raised.",
				Optional:            true,
				Computed:            true,
				Validators:          []validator.String{stringvalidator.OneOf(policySeverities...)},
				PlanModifiers:       keep,
			},
			"title": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: keep,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "What the rule looks for, in one line.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"category": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: keep,
			},
			"owner": schema.StringAttribute{
				MarkdownDescription: "Who maintains the rule.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"taxonomy_mappings": schema.ListAttribute{
				MarkdownDescription: "Framework codes the rule maps to, e.g. `OWASP-ASI02`.",
				ElementType:         types.StringType,
				Computed:            true,
				PlanModifiers:       []planmodifier.List{listplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				MarkdownDescription: "RFC 3339 creation timestamp.",
				Computed:            true,
				PlanModifiers:       keep,
			},
		},
	}
}

func (r *threatDetectionRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Manifold)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Manifold, got %T.", req.ProviderData))
		return
	}
	r.client = c
}

func (r *threatDetectionRuleResource) get(ctx context.Context, id string) (*client.GetThreatDetectionRuleResponse, error) {
	out, err := r.client.GetThreatDetectionRuleWithResponse(ctx, id)
	if err == nil && out.JSON200 == nil {
		err = client.NewAPIError(out.StatusCode(), out.Body)
	}
	return out, err
}

func (r *threatDetectionRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan threatDetectionRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := plan.ID.ValueString()
	out, err := r.get(ctx, id)
	if client.IsNotFound(err) {
		addRuleNotFound(&resp.Diagnostics, id)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read detection rule", err.Error())
		return
	}

	current, diags := newThreatDetectionRuleModel(ctx, ruleSummary(*out.JSON200))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := changedTuning(plan, current)
	if body == (client.ThreatDetectionRuleUpdate{}) {
		r.setState(ctx, *out.JSON200, out.HTTPResponse, &resp.State, resp.Private, &resp.Diagnostics)
		return
	}

	etag := out.HTTPResponse.Header.Get("ETag")
	if etag == "" {
		resp.Diagnostics.AddError("Missing ETag for detection rule",
			"Reading the rule returned no ETag, so the change can't be guarded against concurrent edits and was not sent.")
		return
	}
	r.patch(ctx, id, &etag, body, &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *threatDetectionRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state threatDetectionRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := r.get(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		// An error would also fail plans that drop the resource, removed blocks included as OpenTofu refreshes them, so ModifyPlan blocks the re-create instead.
		if !state.Title.IsNull() { // imports carry only the id and Terraform reports those itself
			resp.Diagnostics.AddWarning("Detection rule no longer exists",
				fmt.Sprintf("Detection rule %q was not found, so it was removed from state. It may have been renamed or retired.", state.ID.ValueString()))
		}
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read detection rule", err.Error())
		return
	}

	r.setState(ctx, *out.JSON200, out.HTTPResponse, &resp.State, resp.Private, &resp.Diagnostics)
}

// ModifyPlan checks an adopted id exists, so a renamed or retired rule fails the plan rather than the apply.
func (r *threatDetectionRuleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.client == nil {
		return
	}
	var planID, stateID types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("id"), &planID)...)
	if !req.State.Raw.IsNull() {
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &stateID)...)
	}
	if resp.Diagnostics.HasError() || planID.IsUnknown() || planID.Equal(stateID) {
		return
	}

	_, err := r.get(ctx, planID.ValueString())
	if client.IsNotFound(err) {
		addRuleNotFound(&resp.Diagnostics, planID.ValueString())
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read detection rule", err.Error())
	}
}

func addRuleNotFound(diags *diag.Diagnostics, id string) {
	diags.AddAttributeError(path.Root("id"), "Detection rule not found",
		fmt.Sprintf("No detection rule has id %q. Rules can't be created, only tuned, and an id can stop existing when a rule is renamed or retired. "+
			"Find the current id with the manifold_threat_detection_rules data source and set it here, or remove this resource from the configuration.", id))
}

func (r *threatDetectionRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state threatDetectionRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	etag, d := readETag(ctx, req.Private, "detection rule")
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := changedTuning(plan, state)
	if body == (client.ThreatDetectionRuleUpdate{}) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	r.patch(ctx, plan.ID.ValueString(), etag, body, &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *threatDetectionRuleResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Rules can't be deleted and their defaults aren't exposed, so destroy only forgets the rule.
}

func (r *threatDetectionRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *threatDetectionRuleResource) patch(ctx context.Context, id string, etag *string, body client.ThreatDetectionRuleUpdate, state stateSetter, private privateState, diags *diag.Diagnostics) {
	out, err := r.client.UpdateThreatDetectionRuleWithResponse(ctx, id, &client.UpdateThreatDetectionRuleParams{IfMatch: etag}, body)
	if err == nil && out.JSON200 == nil {
		err = client.NewAPIError(out.StatusCode(), out.Body)
	}
	if client.IsPreconditionFailed(err) {
		diags.AddError("Detection rule changed outside Terraform",
			"The rule was retuned after the last refresh, so this change was rejected rather than overwriting it. Run plan again to review the current state.")
		return
	}
	if err != nil {
		diags.AddError("Unable to update detection rule", err.Error())
		return
	}
	r.setState(ctx, *out.JSON200, out.HTTPResponse, state, private, diags)
}

// changedTuning sends only configured values that differ, as the API rejects an empty PATCH.
func changedTuning(plan, current threatDetectionRuleModel) client.ThreatDetectionRuleUpdate {
	var u client.ThreatDetectionRuleUpdate
	if !plan.Enabled.IsUnknown() && !plan.Enabled.IsNull() && !plan.Enabled.Equal(current.Enabled) {
		u.Enabled = plan.Enabled.ValueBoolPointer()
	}
	if !plan.Severity.IsUnknown() && !plan.Severity.IsNull() && !plan.Severity.Equal(current.Severity) {
		s := client.SeverityInput(plan.Severity.ValueString())
		u.Severity = &s
	}
	return u
}

func (r *threatDetectionRuleResource) setState(ctx context.Context, rule client.ThreatDetectionRule, httpResp *http.Response, state stateSetter, private privateState, diags *diag.Diagnostics) {
	m, d := newThreatDetectionRuleModel(ctx, ruleSummary(rule))
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	diags.Append(state.Set(ctx, &m)...)
	diags.Append(storeETag(ctx, httpResp, private)...)
}
