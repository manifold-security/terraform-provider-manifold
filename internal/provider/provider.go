package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

const defaultAuthDomain = "auth.manifoldsecurity.io"

var _ provider.Provider = &manifoldProvider{}

type manifoldProvider struct {
	version string
}

type manifoldProviderModel struct {
	Endpoint     types.String `tfsdk:"endpoint"`
	AuthDomain   types.String `tfsdk:"auth_domain"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	Organization types.String `tfsdk:"organization"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &manifoldProvider{version: version}
	}
}

func (p *manifoldProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "manifold"
	resp.Version = p.version
}

func (p *manifoldProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage Manifold resources through the management API. Authenticates as an OIDC client (OAuth2 client credentials) created under **Settings → Access → Credentials** in the Manifold dashboard.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Root URL of your Manifold instance, e.g. `https://acme.app.manifoldsecurity.io`. Can also be set with `MANIFOLD_ENDPOINT`.",
				Optional:            true,
			},
			"auth_domain": schema.StringAttribute{
				MarkdownDescription: "Host that issues access tokens. Defaults to `" + defaultAuthDomain + "`. Can also be set with `MANIFOLD_AUTH_DOMAIN`.",
				Optional:            true,
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "OIDC client ID. Can also be set with `MANIFOLD_CLIENT_ID`.",
				Optional:            true,
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "OIDC client secret. Can also be set with `MANIFOLD_CLIENT_SECRET`.",
				Optional:            true,
				Sensitive:           true,
			},
			"organization": schema.StringAttribute{
				MarkdownDescription: "Organization the token is scoped to, as shown with the client in the dashboard. Can also be set with `MANIFOLD_ORGANIZATION`.",
				Optional:            true,
			},
		},
	}
}

func (p *manifoldProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg manifoldProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	type setting struct {
		attr     string
		env      string
		value    types.String
		fallback string
		out      *string
	}
	var c client.Config
	var authDomain string
	settings := []setting{
		{"endpoint", "MANIFOLD_ENDPOINT", cfg.Endpoint, "", &c.Endpoint},
		{"auth_domain", "MANIFOLD_AUTH_DOMAIN", cfg.AuthDomain, defaultAuthDomain, &authDomain},
		{"client_id", "MANIFOLD_CLIENT_ID", cfg.ClientID, "", &c.ClientID},
		{"client_secret", "MANIFOLD_CLIENT_SECRET", cfg.ClientSecret, "", &c.ClientSecret},
		{"organization", "MANIFOLD_ORGANIZATION", cfg.Organization, "", &c.Organization},
	}
	for _, s := range settings {
		if s.value.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(s.attr), "Unknown provider configuration",
				fmt.Sprintf("%s depends on a value not known until apply. Set it statically or with %s.", s.attr, s.env))
			continue
		}
		v := s.value.ValueString()
		if v == "" {
			v = os.Getenv(s.env)
		}
		if v == "" {
			v = s.fallback
		}
		if v == "" {
			resp.Diagnostics.AddAttributeError(path.Root(s.attr), "Missing provider configuration",
				fmt.Sprintf("Set %s in the provider block or with %s.", s.attr, s.env))
			continue
		}
		*s.out = v
	}
	if resp.Diagnostics.HasError() {
		return
	}

	c.TokenURL = "https://" + authDomain + "/oauth/token"
	c.UserAgent = fmt.Sprintf("terraform-provider-manifold/%s (+https://github.com/manifold-security/terraform-provider-manifold) Terraform/%s", p.version, req.TerraformVersion)

	m, err := client.New(ctx, c)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Manifold client", err.Error())
		return
	}
	resp.DataSourceData = m
	resp.ResourceData = m
}

func (p *manifoldProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *manifoldProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewGovernancePolicyDataSource,
		NewGovernancePoliciesDataSource,
	}
}
