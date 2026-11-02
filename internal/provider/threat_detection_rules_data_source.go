package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

var _ datasource.DataSourceWithConfigure = &threatDetectionRulesDataSource{}

type threatDetectionRulesDataSource struct {
	client *client.Manifold
}

type threatDetectionRulesModel struct {
	IDs        types.Set    `tfsdk:"ids"`
	Categories types.Set    `tfsdk:"categories"`
	Severities types.Set    `tfsdk:"severities"`
	Enabled    types.Bool   `tfsdk:"enabled"`
	Framework  types.String `tfsdk:"framework"`
	Query      types.String `tfsdk:"query"`
	Rules      types.List   `tfsdk:"rules"`
}

func NewThreatDetectionRulesDataSource() datasource.DataSource {
	return &threatDetectionRulesDataSource{}
}

func (d *threatDetectionRulesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_detection_rules"
}

func (d *threatDetectionRulesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists threat detection rules and how each is tuned. Filters combine with AND; values within one filter combine with OR. Needs the `read:threats` scope.",
		Attributes: map[string]schema.Attribute{
			"ids": schema.SetAttribute{
				MarkdownDescription: "Only these rule ids.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"categories": schema.SetAttribute{
				MarkdownDescription: "Only rules in these categories.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"severities": enumSet("Only rules with these severities.", policySeverities),
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Only rules that run, or only those switched off.",
				Optional:            true,
			},
			"framework": schema.StringAttribute{
				MarkdownDescription: "Only rules mapping to this taxonomy code, e.g. `OWASP-ASI02`.",
				Optional:            true,
			},
			"query": schema.StringAttribute{
				MarkdownDescription: "Case-insensitive substring match on id, title or description.",
				Optional:            true,
			},
			"rules": schema.ListNestedAttribute{
				MarkdownDescription: "Matching rules, most recently tuned first.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: threatDetectionRuleAttributes(),
				},
			},
		},
	}
}

func (d *threatDetectionRulesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *threatDetectionRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg threatDetectionRulesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := client.ListThreatDetectionRulesParams{
		Enabled:   cfg.Enabled.ValueBoolPointer(),
		Framework: cfg.Framework.ValueStringPointer(),
		Q:         cfg.Query.ValueStringPointer(),
	}
	for _, err := range []error{
		setToEnums(ctx, cfg.IDs, &params.DetectionRuleId),
		setToEnums(ctx, cfg.Categories, &params.Category),
		setToEnums(ctx, cfg.Severities, &params.Severity),
	} {
		if err != nil {
			resp.Diagnostics.AddError("Invalid filter", err.Error())
			return
		}
	}

	rules, err := d.client.ListAllThreatDetectionRules(ctx, params)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list detection rules", err.Error())
		return
	}

	items := make([]threatDetectionRuleItemModel, 0, len(rules))
	for _, r := range rules {
		m, diags := newThreatDetectionRuleModel(ctx, r)
		resp.Diagnostics.Append(diags...)
		items = append(items, threatDetectionRuleItemModel{threatDetectionRuleModel: m, UpdatedAt: timestamp(r.UpdatedAt)})
	}
	if resp.Diagnostics.HasError() {
		return
	}

	list, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: threatDetectionRuleAttrTypes()}, items)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg.Rules = list
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
