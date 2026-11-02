package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

var _ datasource.DataSourceWithConfigure = &deviceGroupsDataSource{}

type deviceGroupsDataSource struct {
	client *client.Manifold
}

type deviceGroupsModel struct {
	Groups types.List `tfsdk:"groups"`
}

type deviceGroupModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	MemberCount types.Int64  `tfsdk:"member_count"`
	CreatedAt   types.String `tfsdk:"created_at"`
}

var deviceGroupAttrTypes = map[string]attr.Type{
	"id":           types.StringType,
	"name":         types.StringType,
	"description":  types.StringType,
	"member_count": types.Int64Type,
	"created_at":   types.StringType,
}

func NewDeviceGroupsDataSource() datasource.DataSource {
	return &deviceGroupsDataSource{}
}

func (d *deviceGroupsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_device_groups"
}

func (d *deviceGroupsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the custom endpoint groups admins have defined for the device fleet. Needs the `read:fleet` scope.",
		Attributes: map[string]schema.Attribute{
			"groups": schema.ListNestedAttribute{
				MarkdownDescription: "Every custom group, ordered by name.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The group's identifier, a UUID.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The group's name, unique across the fleet.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "Free-text description; empty when unset.",
							Computed:            true,
						},
						"member_count": schema.Int64Attribute{
							MarkdownDescription: "Number of devices currently in the group.",
							Computed:            true,
						},
						"created_at": schema.StringAttribute{
							MarkdownDescription: "RFC 3339 creation timestamp.",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *deviceGroupsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *deviceGroupsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	r, err := d.client.ListDeviceGroupsWithResponse(ctx)
	if err == nil && r.JSON200 == nil {
		err = client.NewAPIError(r.StatusCode(), r.Body)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to list device groups", err.Error())
		return
	}

	items := make([]deviceGroupModel, 0, len(r.JSON200.Groups))
	for _, g := range r.JSON200.Groups {
		items = append(items, deviceGroupModel{
			ID:          types.StringValue(g.Id.String()),
			Name:        types.StringValue(g.Name),
			Description: types.StringValue(g.Description),
			MemberCount: types.Int64Value(int64(g.MemberCount)),
			CreatedAt:   timestamp(g.CreatedAt),
		})
	}
	list, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: deviceGroupAttrTypes}, items)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &deviceGroupsModel{Groups: list})...)
}
