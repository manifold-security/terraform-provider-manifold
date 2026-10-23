package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

const etagKey = "etag"

var (
	_ resource.ResourceWithConfigure      = &governancePolicyResource{}
	_ resource.ResourceWithImportState    = &governancePolicyResource{}
	_ resource.ResourceWithValidateConfig = &governancePolicyResource{}
)

type governancePolicyResource struct {
	client *client.Manifold
}

func NewGovernancePolicyResource() resource.Resource {
	return &governancePolicyResource{}
}

func (r *governancePolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_policy"
}

func (r *governancePolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}

	resp.Schema = schema.Schema{
		MarkdownDescription: "A customer-authored governance policy: a Cedar rule and what happens when it matches. Manifold-managed policies are read-only and cannot be imported.\n\n" +
			"Updates send the `ETag` from the last refresh as `If-Match`, so a policy edited elsewhere after the plan was made fails the apply instead of being overwritten.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The policy's identifier, a server-assigned UUID.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"title": schema.StringAttribute{
				Required:   true,
				Validators: []validator.String{stringvalidator.LengthBetween(1, 255)},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "What the policy detects and why it matters.",
				Required:            true,
			},
			"category": schema.StringAttribute{
				MarkdownDescription: "One of `ACCESS`, `EXECUTION`, `DATA`, `USAGE`.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.OneOf(policyCategories...)},
			},
			"action": schema.StringAttribute{
				MarkdownDescription: "What the policy does on a match: `alert`, `advise`, `correct`, `ask`, `block` or `block_session`. `advise` and `correct` require `response_message`.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.OneOf(policyActions...)},
			},
			"cedar_policy": schema.StringAttribute{
				MarkdownDescription: "The Cedar rule the policy is evaluated from. It must contain a `forbid`; the API type-checks it on write.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"severity": schema.StringAttribute{
				MarkdownDescription: "Severity carried by the violations this policy produces: `critical`, `high`, `medium` or `low`. Defaults to `medium`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("medium"),
				Validators:          []validator.String{stringvalidator.OneOf(policySeverities...)},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the policy is evaluated at all. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"priority": schema.Int32Attribute{
				MarkdownDescription: "Attribution order when several blocking policies match one event; the highest supplies the block message. Defaults to `0`.",
				Optional:            true,
				Computed:            true,
				Default:             int32default.StaticInt32(0),
			},
			"action_options": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Default: objectdefault.StaticValue(types.ObjectValueMust(actionOptionsAttrTypes, map[string]attr.Value{
					"notify_user": types.BoolValue(false),
				})),
				Attributes: map[string]schema.Attribute{
					"notify_user": schema.BoolAttribute{
						MarkdownDescription: "Whether the developer is notified when the policy matches. Defaults to `false`.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
					},
				},
			},
			"taxonomy_mappings": schema.ListAttribute{
				MarkdownDescription: "Framework codes the policy maps to, e.g. `OWASP-ASI02`.",
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
			},
			"response_message": schema.StringAttribute{
				MarkdownDescription: "What the agent is told when the policy blocks, or the directive an `advise`/`correct` policy hands the model. A Go template; the API validates its placeholders.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"is_managed": schema.BoolAttribute{
				MarkdownDescription: "Always `false` for a policy managed here.",
				Computed:            true,
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"owner": schema.StringAttribute{
				MarkdownDescription: "The client that created the policy.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"created_at": schema.StringAttribute{
				MarkdownDescription: "RFC 3339 creation timestamp.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"updated_at": schema.StringAttribute{
				MarkdownDescription: "RFC 3339 timestamp of the last change.",
				Computed:            true,
			},
		},
	}
}

func (r *governancePolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *governancePolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg governancePolicyDetailModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() || cfg.Action.IsUnknown() || cfg.ResponseMessage.IsUnknown() {
		return
	}
	if a := cfg.Action.ValueString(); (a == "advise" || a == "correct") && cfg.ResponseMessage.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("response_message"), "Missing response_message",
			fmt.Sprintf("Policies with action %q hand response_message to the model, so it must be set.", a))
	}
}

func (r *governancePolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan governancePolicyDetailModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	f, diags := authoredFields(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := r.client.CreateGovernancePolicyWithResponse(ctx, client.GovernancePolicyCreate{
		Title:            f.title,
		Description:      f.description,
		Category:         f.category,
		Action:           f.action,
		CedarPolicy:      f.cedar,
		Severity:         &f.severity,
		Enabled:          &f.enabled,
		Priority:         &f.priority,
		ActionOptions:    &f.actionOptions,
		TaxonomyMappings: &f.taxonomy,
		ResponseMessage:  plan.ResponseMessage.ValueStringPointer(),
	})
	if err == nil && out.JSON201 == nil {
		err = client.NewAPIError(out.StatusCode(), out.Body)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to create governance policy", err.Error())
		return
	}

	r.setState(ctx, *out.JSON201, out.HTTPResponse, &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *governancePolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state governancePolicyDetailModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := uuid.Parse(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid policy id", err.Error())
		return
	}

	out, err := r.client.GetGovernancePolicyWithResponse(ctx, id)
	if err == nil && out.JSON200 == nil {
		err = client.NewAPIError(out.StatusCode(), out.Body)
	}
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read governance policy", err.Error())
		return
	}

	r.setState(ctx, *out.JSON200, out.HTTPResponse, &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *governancePolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state governancePolicyDetailModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := changedFields(ctx, plan, state)
	resp.Diagnostics.Append(diags...)
	etag, d := readETag(ctx, req.Private)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The API rejects an empty PATCH, and with no authored field changed the prior state already matches the plan.
	if body == (client.GovernancePolicyUpdate{}) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}

	id, err := uuid.Parse(plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid policy id", err.Error())
		return
	}
	out, err := r.client.UpdateGovernancePolicyWithResponse(ctx, id, &client.UpdateGovernancePolicyParams{IfMatch: etag}, body)
	if err == nil && out.JSON200 == nil {
		err = client.NewAPIError(out.StatusCode(), out.Body)
	}
	if client.IsPreconditionFailed(err) {
		resp.Diagnostics.AddError("Governance policy changed outside Terraform",
			"The policy was modified after the last refresh, so this update was rejected rather than overwriting it. Run plan again to review the current state.")
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to update governance policy", err.Error())
		return
	}

	r.setState(ctx, *out.JSON200, out.HTTPResponse, &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *governancePolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state governancePolicyDetailModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	etag, d := readETag(ctx, req.Private)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := uuid.Parse(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid policy id", err.Error())
		return
	}
	out, err := r.client.DeleteGovernancePolicyWithResponse(ctx, id, &client.DeleteGovernancePolicyParams{IfMatch: etag})
	if err == nil && out.StatusCode() != http.StatusNoContent {
		err = client.NewAPIError(out.StatusCode(), out.Body)
	}
	if client.IsNotFound(err) {
		return
	}
	if client.IsPreconditionFailed(err) {
		resp.Diagnostics.AddError("Governance policy changed outside Terraform",
			"The policy was modified after the last refresh, so it was not deleted. Run plan again to review the current state.")
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete governance policy", err.Error())
	}
}

func (r *governancePolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := uuid.Parse(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("Expected a policy UUID, got %q.", req.ID))
		return
	}

	out, err := r.client.GetGovernancePolicyWithResponse(ctx, id)
	if err == nil && out.JSON200 == nil {
		err = client.NewAPIError(out.StatusCode(), out.Body)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read governance policy", err.Error())
		return
	}
	if out.JSON200.IsManaged {
		resp.Diagnostics.AddError("Cannot import a managed policy",
			fmt.Sprintf("%q is maintained by Manifold and cannot be edited or deleted. Read it with the manifold_governance_policy data source instead.", out.JSON200.Title))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id.String())...)
}

type policyFields struct {
	title, description, cedar string
	category                  client.GovernancePolicyCategory
	action                    client.GovernanceAction
	severity                  client.SeverityInput
	enabled                   bool
	priority                  int32
	actionOptions             client.GovernancePolicyActionOptionsInput
	taxonomy                  []string
}

func authoredFields(ctx context.Context, m governancePolicyDetailModel) (policyFields, diag.Diagnostics) {
	var diags diag.Diagnostics

	var opts struct {
		NotifyUser types.Bool `tfsdk:"notify_user"`
	}
	diags.Append(m.ActionOptions.As(ctx, &opts, basetypes.ObjectAsOptions{})...)
	notify := opts.NotifyUser.ValueBool()

	taxonomy := []string{}
	diags.Append(m.TaxonomyMappings.ElementsAs(ctx, &taxonomy, false)...)

	return policyFields{
		title:         m.Title.ValueString(),
		description:   m.Description.ValueString(),
		cedar:         m.CedarPolicy.ValueString(),
		category:      client.GovernancePolicyCategory(m.Category.ValueString()),
		action:        client.GovernanceAction(m.Action.ValueString()),
		severity:      client.SeverityInput(m.Severity.ValueString()),
		enabled:       m.Enabled.ValueBool(),
		priority:      m.Priority.ValueInt32(),
		actionOptions: client.GovernancePolicyActionOptionsInput{NotifyUser: &notify},
		taxonomy:      taxonomy,
	}, diags
}

// changedFields sends only what the plan changes: the API re-validates every field it receives, so
// re-sending an untouched cedar_policy would make any edit fail once the Cedar schema has moved on.
func changedFields(ctx context.Context, plan, state governancePolicyDetailModel) (client.GovernancePolicyUpdate, diag.Diagnostics) {
	f, diags := authoredFields(ctx, plan)
	var u client.GovernancePolicyUpdate
	if !plan.Title.Equal(state.Title) {
		u.Title = &f.title
	}
	if !plan.Description.Equal(state.Description) {
		u.Description = &f.description
	}
	if !plan.Category.Equal(state.Category) {
		u.Category = &f.category
	}
	if !plan.Action.Equal(state.Action) {
		u.Action = &f.action
	}
	if !plan.CedarPolicy.Equal(state.CedarPolicy) {
		u.CedarPolicy = &f.cedar
	}
	if !plan.Severity.Equal(state.Severity) {
		u.Severity = &f.severity
	}
	if !plan.Enabled.Equal(state.Enabled) {
		u.Enabled = &f.enabled
	}
	if !plan.Priority.Equal(state.Priority) {
		u.Priority = &f.priority
	}
	if !plan.ActionOptions.Equal(state.ActionOptions) {
		u.ActionOptions = &f.actionOptions
	}
	if !plan.TaxonomyMappings.Equal(state.TaxonomyMappings) {
		u.TaxonomyMappings = &f.taxonomy
	}
	if !plan.ResponseMessage.Equal(state.ResponseMessage) {
		// An empty string is how the API clears a response message.
		msg := plan.ResponseMessage.ValueString()
		u.ResponseMessage = &msg
	}
	return u, diags
}

type stateSetter interface {
	Set(ctx context.Context, val any) diag.Diagnostics
}

type privateState interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

type privateReader interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
}

func (r *governancePolicyResource) setState(ctx context.Context, p client.GovernancePolicy, httpResp *http.Response, state stateSetter, private privateState, diags *diag.Diagnostics) {
	m, d := newGovernancePolicyDetailModel(ctx, p)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	diags.Append(state.Set(ctx, &m)...)

	var raw []byte
	if etag := httpResp.Header.Get("ETag"); etag != "" {
		raw, _ = json.Marshal(etag)
	}
	diags.Append(private.SetKey(ctx, etagKey, raw)...)
}

func readETag(ctx context.Context, private privateReader) (*string, diag.Diagnostics) {
	raw, diags := private.GetKey(ctx, etagKey)
	if diags.HasError() {
		return nil, diags
	}
	if len(raw) == 0 {
		diags.AddError("Missing ETag for governance policy",
			"The last read of this policy returned no ETag, so the change can't be guarded against concurrent edits and was not sent. Run plan again to refresh it.")
		return nil, diags
	}
	var etag string
	if err := json.Unmarshal(raw, &etag); err != nil {
		diags.AddError("Corrupt private state", err.Error())
		return nil, diags
	}
	return &etag, diags
}
