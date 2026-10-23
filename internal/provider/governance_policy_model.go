package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

type governancePolicyModel struct {
	ID               types.String `tfsdk:"id"`
	Title            types.String `tfsdk:"title"`
	Description      types.String `tfsdk:"description"`
	Category         types.String `tfsdk:"category"`
	Severity         types.String `tfsdk:"severity"`
	Action           types.String `tfsdk:"action"`
	ActionOptions    types.Object `tfsdk:"action_options"`
	Priority         types.Int32  `tfsdk:"priority"`
	Enabled          types.Bool   `tfsdk:"enabled"`
	IsManaged        types.Bool   `tfsdk:"is_managed"`
	Owner            types.String `tfsdk:"owner"`
	TaxonomyMappings types.List   `tfsdk:"taxonomy_mappings"`
	ResponseMessage  types.String `tfsdk:"response_message"`
	CreatedAt        types.String `tfsdk:"created_at"`
}

type governancePolicyDetailModel struct {
	governancePolicyModel
	CedarPolicy types.String `tfsdk:"cedar_policy"`
}

// The resource leaves updated_at out so an in-place update doesn't plan it as unknown; only the data sources expose it.
type governancePolicyItemModel struct {
	governancePolicyModel
	UpdatedAt types.String `tfsdk:"updated_at"`
}

type governancePolicyDataSourceModel struct {
	governancePolicyDetailModel
	UpdatedAt types.String `tfsdk:"updated_at"`
}

var actionOptionsAttrTypes = map[string]attr.Type{
	"notify_user": types.BoolType,
}

// governancePolicyAttributes describes the fields shared by list items and the single-policy detail.
func governancePolicyAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The policy's identifier, a server-assigned UUID.",
			Computed:            true,
		},
		"title": schema.StringAttribute{Computed: true},
		"description": schema.StringAttribute{
			MarkdownDescription: "What the policy detects and why it matters.",
			Computed:            true,
		},
		"category": schema.StringAttribute{
			MarkdownDescription: "One of `ACCESS`, `EXECUTION`, `DATA`, `USAGE`.",
			Computed:            true,
		},
		"severity": schema.StringAttribute{
			MarkdownDescription: "Severity carried by the violations this policy produces.",
			Computed:            true,
		},
		"action": schema.StringAttribute{
			MarkdownDescription: "What the policy does on a match: `alert`, `advise`, `correct`, `ask`, `block` or `block_session`.",
			Computed:            true,
		},
		"action_options": schema.SingleNestedAttribute{
			Computed: true,
			Attributes: map[string]schema.Attribute{
				"notify_user": schema.BoolAttribute{
					MarkdownDescription: "Whether the developer is notified when the policy matches.",
					Computed:            true,
				},
			},
		},
		"priority": schema.Int32Attribute{
			MarkdownDescription: "Attribution order when several blocking policies match one event; the highest supplies the block message.",
			Computed:            true,
		},
		"enabled": schema.BoolAttribute{
			MarkdownDescription: "Whether the policy is evaluated at all.",
			Computed:            true,
		},
		"is_managed": schema.BoolAttribute{
			MarkdownDescription: "True for a Manifold-maintained policy, which cannot be edited or deleted.",
			Computed:            true,
		},
		"owner": schema.StringAttribute{
			MarkdownDescription: "Who maintains the policy.",
			Computed:            true,
		},
		"taxonomy_mappings": schema.ListAttribute{
			MarkdownDescription: "Framework codes the policy maps to, e.g. `OWASP-ASI02`.",
			ElementType:         types.StringType,
			Computed:            true,
		},
		"response_message": schema.StringAttribute{
			MarkdownDescription: "What the agent is told when the policy blocks, or the directive an `advise`/`correct` policy hands the model. Null when unset.",
			Computed:            true,
		},
		"created_at": schema.StringAttribute{
			MarkdownDescription: "RFC 3339 creation timestamp.",
			Computed:            true,
		},
		"updated_at": schema.StringAttribute{
			MarkdownDescription: "RFC 3339 timestamp of the last change.",
			Computed:            true,
		},
	}
}

func governancePolicyAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                types.StringType,
		"title":             types.StringType,
		"description":       types.StringType,
		"category":          types.StringType,
		"severity":          types.StringType,
		"action":            types.StringType,
		"action_options":    types.ObjectType{AttrTypes: actionOptionsAttrTypes},
		"priority":          types.Int32Type,
		"enabled":           types.BoolType,
		"is_managed":        types.BoolType,
		"owner":             types.StringType,
		"taxonomy_mappings": types.ListType{ElemType: types.StringType},
		"response_message":  types.StringType,
		"created_at":        types.StringType,
		"updated_at":        types.StringType,
	}
}

func newGovernancePolicyModel(ctx context.Context, p client.GovernancePolicySummary) (governancePolicyModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	opts, d := types.ObjectValue(actionOptionsAttrTypes, map[string]attr.Value{
		"notify_user": types.BoolValue(p.ActionOptions.NotifyUser),
	})
	diags.Append(d...)

	mappings, d := types.ListValueFrom(ctx, types.StringType, p.TaxonomyMappings)
	diags.Append(d...)

	return governancePolicyModel{
		ID:               types.StringValue(p.PolicyId.String()),
		Title:            types.StringValue(p.Title),
		Description:      types.StringValue(p.Description),
		Category:         types.StringValue(string(p.Category)),
		Severity:         types.StringValue(p.Severity),
		Action:           types.StringValue(string(p.Action)),
		ActionOptions:    opts,
		Priority:         types.Int32Value(p.Priority),
		Enabled:          types.BoolValue(p.Enabled),
		IsManaged:        types.BoolValue(p.IsManaged),
		Owner:            types.StringValue(p.Owner),
		TaxonomyMappings: mappings,
		ResponseMessage:  types.StringPointerValue(p.ResponseMessage),
		CreatedAt:        timestamp(p.CreatedAt),
	}, diags
}

func timestamp(t time.Time) types.String {
	return types.StringValue(t.UTC().Format(time.RFC3339Nano))
}

func newGovernancePolicyDetailModel(ctx context.Context, p client.GovernancePolicy) (governancePolicyDetailModel, diag.Diagnostics) {
	summary := client.GovernancePolicySummary{
		PolicyId:         p.PolicyId,
		Title:            p.Title,
		Description:      p.Description,
		Category:         p.Category,
		Severity:         p.Severity,
		Action:           p.Action,
		ActionOptions:    p.ActionOptions,
		Priority:         p.Priority,
		Enabled:          p.Enabled,
		IsManaged:        p.IsManaged,
		Owner:            p.Owner,
		TaxonomyMappings: p.TaxonomyMappings,
		ResponseMessage:  p.ResponseMessage,
		CreatedAt:        p.CreatedAt,
	}
	m, diags := newGovernancePolicyModel(ctx, summary)
	return governancePolicyDetailModel{
		governancePolicyModel: m,
		CedarPolicy:           types.StringPointerValue(p.CedarPolicy),
	}, diags
}
