package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

var _ datasource.DataSourceWithConfigure = &threatDetectionRuleDataSource{}

type threatDetectionRuleDataSource struct {
	client *client.Manifold
}

func NewThreatDetectionRuleDataSource() datasource.DataSource {
	return &threatDetectionRuleDataSource{}
}

func (d *threatDetectionRuleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_detection_rule"
}

func (d *threatDetectionRuleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := threatDetectionRuleAttributes()
	attrs["id"] = schema.StringAttribute{
		MarkdownDescription: "The rule's identifier.",
		Required:            true,
	}
	attrs["what_it_detects"] = schema.StringAttribute{Computed: true}
	attrs["why_it_matters"] = schema.StringAttribute{Computed: true}
	attrs["potential_impact"] = schema.StringAttribute{Computed: true}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads one threat detection rule, with the text explaining what it detects. Needs the `read:threats` scope.",
		Attributes:          attrs,
	}
}

func (d *threatDetectionRuleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *threatDetectionRuleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg threatDetectionRuleDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r, err := d.client.GetThreatDetectionRuleWithResponse(ctx, cfg.ID.ValueString())
	if err == nil && r.JSON200 == nil {
		err = client.NewAPIError(r.StatusCode(), r.Body)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read detection rule", err.Error())
		return
	}

	rule := *r.JSON200
	m, diags := newThreatDetectionRuleModel(ctx, ruleSummary(rule))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state := threatDetectionRuleDataSourceModel{
		threatDetectionRuleItemModel: threatDetectionRuleItemModel{threatDetectionRuleModel: m, UpdatedAt: timestamp(rule.UpdatedAt)},
		WhatItDetects:                types.StringValue(rule.WhatItDetects),
		WhyItMatters:                 types.StringValue(rule.WhyItMatters),
		PotentialImpact:              types.StringValue(rule.PotentialImpact),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
