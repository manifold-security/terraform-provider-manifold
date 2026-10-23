package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

var _ datasource.DataSourceWithConfigure = &governancePoliciesDataSource{}

var (
	policyCategories = []string{"ACCESS", "EXECUTION", "DATA", "USAGE"}
	policySeverities = []string{"critical", "high", "medium", "low"}
	policyActions    = []string{"alert", "advise", "correct", "ask", "block", "block_session"}
)

type governancePoliciesDataSource struct {
	client *client.Manifold
}

type governancePoliciesModel struct {
	Categories types.Set    `tfsdk:"categories"`
	Severities types.Set    `tfsdk:"severities"`
	Actions    types.Set    `tfsdk:"actions"`
	Enabled    types.Bool   `tfsdk:"enabled"`
	IsManaged  types.Bool   `tfsdk:"is_managed"`
	Framework  types.String `tfsdk:"framework"`
	Query      types.String `tfsdk:"query"`
	Policies   types.List   `tfsdk:"policies"`
}

func NewGovernancePoliciesDataSource() datasource.DataSource {
	return &governancePoliciesDataSource{}
}

func (d *governancePoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_policies"
}

func enumSet(desc string, values []string) schema.SetAttribute {
	return schema.SetAttribute{
		MarkdownDescription: desc,
		ElementType:         types.StringType,
		Optional:            true,
		Validators: []validator.Set{
			setvalidator.ValueStringsAre(stringvalidator.OneOf(values...)),
		},
	}
}

func (d *governancePoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists governance policies, both customer-authored and Manifold-managed. Filters combine with AND; values within one filter combine with OR. List items omit `cedar_policy`; read it with `manifold_governance_policy`.",
		Attributes: map[string]schema.Attribute{
			"categories": enumSet("Only policies in these categories.", policyCategories),
			"severities": enumSet("Only policies with these severities.", policySeverities),
			"actions":    enumSet("Only policies taking these actions.", policyActions),
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Only policies that are (or are not) evaluated.",
				Optional:            true,
			},
			"is_managed": schema.BoolAttribute{
				MarkdownDescription: "`true` for Manifold-managed policies only, `false` for customer-authored only.",
				Optional:            true,
			},
			"framework": schema.StringAttribute{
				MarkdownDescription: "Only policies mapping to this taxonomy code, e.g. `OWASP-ASI02`.",
				Optional:            true,
			},
			"query": schema.StringAttribute{
				MarkdownDescription: "Case-insensitive substring match on id, title or description.",
				Optional:            true,
			},
			"policies": schema.ListNestedAttribute{
				MarkdownDescription: "Matching policies, most recently updated first.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: governancePolicyAttributes(),
				},
			},
		},
	}
}

func (d *governancePoliciesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Manifold)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Manifold, got %T.", req.ProviderData))
		return
	}
	d.client = c
}

func setToEnums[T ~string](ctx context.Context, s types.Set, out **[]T) error {
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	var raw []string
	if diags := s.ElementsAs(ctx, &raw, false); diags.HasError() {
		return fmt.Errorf("decoding set: %v", diags)
	}
	vals := make([]T, len(raw))
	for i, v := range raw {
		vals[i] = T(v)
	}
	*out = &vals
	return nil
}

func (d *governancePoliciesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg governancePoliciesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := client.ListGovernancePoliciesParams{
		Enabled:   cfg.Enabled.ValueBoolPointer(),
		IsManaged: cfg.IsManaged.ValueBoolPointer(),
		Framework: cfg.Framework.ValueStringPointer(),
		Q:         cfg.Query.ValueStringPointer(),
	}
	for _, err := range []error{
		setToEnums(ctx, cfg.Categories, &params.Category),
		setToEnums(ctx, cfg.Severities, &params.Severity),
		setToEnums(ctx, cfg.Actions, &params.Action),
	} {
		if err != nil {
			resp.Diagnostics.AddError("Invalid filter", err.Error())
			return
		}
	}

	policies, err := d.client.ListAllGovernancePolicies(ctx, params)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list governance policies", err.Error())
		return
	}

	items := make([]governancePolicyItemModel, 0, len(policies))
	for _, p := range policies {
		m, diags := newGovernancePolicyModel(ctx, p)
		resp.Diagnostics.Append(diags...)
		items = append(items, governancePolicyItemModel{governancePolicyModel: m, UpdatedAt: timestamp(p.UpdatedAt)})
	}
	if resp.Diagnostics.HasError() {
		return
	}

	list, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: governancePolicyAttrTypes()}, items)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg.Policies = list
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
