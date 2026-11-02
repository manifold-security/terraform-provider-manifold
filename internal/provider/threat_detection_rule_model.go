package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

type threatDetectionRuleModel struct {
	ID               types.String `tfsdk:"id"`
	Title            types.String `tfsdk:"title"`
	Description      types.String `tfsdk:"description"`
	Category         types.String `tfsdk:"category"`
	Severity         types.String `tfsdk:"severity"`
	Enabled          types.Bool   `tfsdk:"enabled"`
	Owner            types.String `tfsdk:"owner"`
	TaxonomyMappings types.List   `tfsdk:"taxonomy_mappings"`
	CreatedAt        types.String `tfsdk:"created_at"`
}

// As with governance policies, updated_at is left out of the resource so a retune doesn't plan it as unknown.
type threatDetectionRuleItemModel struct {
	threatDetectionRuleModel
	UpdatedAt types.String `tfsdk:"updated_at"`
}

type threatDetectionRuleDataSourceModel struct {
	threatDetectionRuleItemModel
	WhatItDetects   types.String `tfsdk:"what_it_detects"`
	WhyItMatters    types.String `tfsdk:"why_it_matters"`
	PotentialImpact types.String `tfsdk:"potential_impact"`
}

func threatDetectionRuleAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The rule's identifier, the `detection_rule_id` threats name.",
			Computed:            true,
		},
		"title": schema.StringAttribute{Computed: true},
		"description": schema.StringAttribute{
			MarkdownDescription: "What the rule looks for, in one line.",
			Computed:            true,
		},
		"category": schema.StringAttribute{Computed: true},
		"severity": schema.StringAttribute{
			MarkdownDescription: "Severity the threats this rule raises inherit.",
			Computed:            true,
		},
		"enabled": schema.BoolAttribute{
			MarkdownDescription: "Whether the rule runs. A disabled rule raises nothing new.",
			Computed:            true,
		},
		"owner": schema.StringAttribute{
			MarkdownDescription: "Who maintains the rule.",
			Computed:            true,
		},
		"taxonomy_mappings": schema.ListAttribute{
			MarkdownDescription: "Framework codes the rule maps to, e.g. `OWASP-ASI02`.",
			ElementType:         types.StringType,
			Computed:            true,
		},
		"created_at": schema.StringAttribute{
			MarkdownDescription: "RFC 3339 creation timestamp.",
			Computed:            true,
		},
		"updated_at": schema.StringAttribute{
			MarkdownDescription: "RFC 3339 timestamp of the last retune.",
			Computed:            true,
		},
	}
}

func threatDetectionRuleAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                types.StringType,
		"title":             types.StringType,
		"description":       types.StringType,
		"category":          types.StringType,
		"severity":          types.StringType,
		"enabled":           types.BoolType,
		"owner":             types.StringType,
		"taxonomy_mappings": types.ListType{ElemType: types.StringType},
		"created_at":        types.StringType,
		"updated_at":        types.StringType,
	}
}

func newThreatDetectionRuleModel(ctx context.Context, r client.ThreatDetectionRuleSummary) (threatDetectionRuleModel, diag.Diagnostics) {
	mappings, diags := types.ListValueFrom(ctx, types.StringType, r.TaxonomyMappings)
	return threatDetectionRuleModel{
		ID:               types.StringValue(r.DetectionRuleId),
		Title:            types.StringValue(r.Title),
		Description:      types.StringValue(r.Description),
		Category:         types.StringValue(r.Category),
		Severity:         types.StringValue(r.Severity),
		Enabled:          types.BoolValue(r.Enabled),
		Owner:            types.StringValue(r.Owner),
		TaxonomyMappings: mappings,
		CreatedAt:        timestamp(r.CreatedAt),
	}, diags
}

func ruleSummary(r client.ThreatDetectionRule) client.ThreatDetectionRuleSummary {
	return client.ThreatDetectionRuleSummary{
		DetectionRuleId:  r.DetectionRuleId,
		Title:            r.Title,
		Description:      r.Description,
		Category:         r.Category,
		Severity:         r.Severity,
		Enabled:          r.Enabled,
		Owner:            r.Owner,
		TaxonomyMappings: r.TaxonomyMappings,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
	}
}
