package provider

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

var _ datasource.DataSourceWithConfigure = &governancePolicyDataSource{}

type governancePolicyDataSource struct {
	client *client.Manifold
}

func NewGovernancePolicyDataSource() datasource.DataSource {
	return &governancePolicyDataSource{}
}

func (d *governancePolicyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_policy"
}

func (d *governancePolicyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := governancePolicyAttributes()
	attrs["id"] = schema.StringAttribute{
		MarkdownDescription: "The policy's identifier, a UUID.",
		Required:            true,
	}
	attrs["cedar_policy"] = schema.StringAttribute{
		MarkdownDescription: "The Cedar expression the policy is evaluated from. Null for managed policies that keep it internal.",
		Computed:            true,
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads one governance policy, including the Cedar rule behind it.",
		Attributes:          attrs,
	}
}

func (d *governancePolicyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *governancePolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg governancePolicyDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := uuid.Parse(cfg.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid policy id", err.Error())
		return
	}

	r, err := d.client.GetGovernancePolicyWithResponse(ctx, id)
	if err == nil && r.JSON200 == nil {
		err = client.NewAPIError(r.StatusCode(), r.Body)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read governance policy", err.Error())
		return
	}

	m, diags := newGovernancePolicyDetailModel(ctx, *r.JSON200)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state := governancePolicyDataSourceModel{governancePolicyDetailModel: m, UpdatedAt: timestamp(r.JSON200.UpdatedAt)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
