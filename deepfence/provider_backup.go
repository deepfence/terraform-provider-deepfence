package deepfence

//
//import (
//	"context"
//	"fmt"
//	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
//	"github.com/aws/smithy-go/logging"
//	cctypes "github.com/deepfence/terraform-provider-deepfence/deepfence/internal/types"
//	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/validate"
//	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
//	"github.com/hashicorp/go-hclog"
//	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
//	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
//	"github.com/hashicorp/terraform-plugin-framework/datasource"
//	"github.com/hashicorp/terraform-plugin-framework/provider"
//	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
//	"github.com/hashicorp/terraform-plugin-framework/resource"
//	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
//	"github.com/hashicorp/terraform-plugin-framework/types"
//	"github.com/hashicorp/terraform-plugin-log/tflog"
//	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
//	//"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
//	"time"
//)
//
//// Copyright (c) HashiCorp, Inc.
//// SPDX-License-Identifier: MPL-2.0
//
//const (
//	defaultMaxRetries         = 25
//	defaultAssumeRoleDuration = 1 * time.Hour
//)
//
//var Version = "dev"
//
//// providerData is returned from the provider's Configure method and
//// is passed to each resource and data source in their Configure methods.
//type providerData struct {
//	region  string
//	roleARN string
//}
//
//func (p *providerData) Region(_ context.Context) string {
//	return p.region
//}
//
//func (p *providerData) RoleARN(_ context.Context) string {
//	return p.roleARN
//}
//
//type ccProvider struct {
//	providerData *providerData // Used in acceptance tests.
//}
//
//func New() provider.Provider {
//	return &ccProvider{}
//}
//
//// ProviderData is used in acceptance testing to get access to configured API client etc.
//func (p *ccProvider) ProviderData() any {
//	return p.providerData
//}
//
//func (p *ccProvider) Metadata(ctx context.Context, request provider.MetadataRequest, response *provider.MetadataResponse) {
//	response.TypeName = "aws_multi_account"
//	response.Version = Version
//}
//
//func (p *ccProvider) Schema(ctx context.Context, request provider.SchemaRequest, response *provider.SchemaResponse) {
//	response.Schema = schema.Schema{
//		Attributes: map[string]schema.Attribute{
//			"access_key": schema.StringAttribute{
//				Description: "This is the AWS access key. It must be provided, but it can also be sourced from the `AWS_ACCESS_KEY_ID` environment variable, or via a shared credentials file if `profile` is specified.",
//				Optional:    true,
//			},
//			"assume_role": schema.SingleNestedAttribute{
//				Attributes: map[string]schema.Attribute{
//					"duration": schema.StringAttribute{
//						CustomType: cctypes.DurationType,
//						Description: "Duration of the assume role session. You can provide a value from 15 minutes up to the maximum session duration setting for the role. " +
//							cctypes.DurationType.Description() +
//							fmt.Sprintf(" Default value is %s", defaultAssumeRoleDuration),
//						Optional: true,
//					},
//					"external_id": schema.StringAttribute{
//						Description: "External identifier to use when assuming the role.",
//						Optional:    true,
//					},
//					"policy": schema.StringAttribute{
//						Description: "IAM policy in JSON format to use as a session policy. The effective permissions for the session will be the intersection between this polcy and the role's policies.",
//						Optional:    true,
//						Validators: []validator.String{
//							stringvalidator.LengthAtMost(2048),
//							validate.StringIsJsonObject(),
//						},
//					},
//					"policy_arns": schema.ListAttribute{
//						ElementType: types.StringType,
//						Description: "Amazon Resource Names (ARNs) of IAM Policies to use as managed session policies. The effective permissions for the session will be the intersection between these polcy and the role's policies.",
//						Optional:    true,
//						Validators: []validator.List{
//							listvalidator.ValueStringsAre(validate.IAMPolicyARN()),
//						},
//					},
//					"role_arn": schema.StringAttribute{
//						Description: "Amazon Resource Name (ARN) of the IAM Role to assume.",
//						Required:    true,
//						Validators: []validator.String{
//							validate.ARN(),
//						},
//					},
//					"session_name": schema.StringAttribute{
//						Description: "Session name to use when assuming the role.",
//						Optional:    true,
//					},
//					"tags": schema.MapAttribute{
//						ElementType: types.StringType,
//						Description: "Map of assume role session tags.",
//						Optional:    true,
//					},
//					"transitive_tag_keys": schema.SetAttribute{
//						ElementType: types.StringType,
//						Description: "Set of assume role session tag keys to pass to any subsequent sessions.",
//						Optional:    true,
//					},
//				},
//				Optional:    true,
//				Description: "An `assume_role` block (documented below). Only one `assume_role` block may be in the configuration.",
//			},
//			"assume_role_with_web_identity": schema.SingleNestedAttribute{
//				Attributes: map[string]schema.Attribute{
//					"duration": schema.StringAttribute{
//						CustomType: cctypes.DurationType,
//						Description: "Duration of the assume role session. You can provide a value from 15 minutes up to the maximum session duration setting for the role. " +
//							cctypes.DurationType.Description() +
//							fmt.Sprintf(" Default value is %s", defaultAssumeRoleDuration),
//						Optional: true,
//					},
//					"policy": schema.StringAttribute{
//						Description: "IAM policy in JSON format to use as a session policy. The effective permissions for the session will be the intersection between this polcy and the role's policies.",
//						Optional:    true,
//						Validators: []validator.String{
//							stringvalidator.LengthAtMost(2048),
//							validate.StringIsJsonObject(),
//						},
//					},
//					"policy_arns": schema.ListAttribute{
//						ElementType: types.StringType,
//						Description: "Amazon Resource Names (ARNs) of IAM Policies to use as managed session policies. The effective permissions for the session will be the intersection between these polcy and the role's policies.",
//						Optional:    true,
//						Validators: []validator.List{
//							listvalidator.ValueStringsAre(validate.IAMPolicyARN()),
//						},
//					},
//					"role_arn": schema.StringAttribute{
//						Description: "Amazon Resource Name (ARN) of the IAM Role to assume. Can also be set with the environment variable `AWS_ROLE_ARN`.",
//						Required:    true,
//						Validators: []validator.String{
//							validate.ARN(),
//						},
//					},
//					"session_name": schema.StringAttribute{
//						Description: "Session name to use when assuming the role. Can also be set with the environment variable `AWS_ROLE_SESSION_NAME`.",
//						Optional:    true,
//					},
//					"web_identity_token": schema.StringAttribute{
//						Description: "The value of a web identity token from an OpenID Connect (OIDC) or OAuth provider. One of `web_identity_token` or `web_identity_token_file` is required.",
//						Optional:    true,
//						Validators: []validator.String{
//							stringvalidator.LengthBetween(4, 20000),
//						},
//					},
//					"web_identity_token_file": schema.StringAttribute{
//						Description: "File containing a web identity token from an OpenID Connect (OIDC) or OAuth provider. Can also be set with the  environment variable`AWS_WEB_IDENTITY_TOKEN_FILE`. One of `web_identity_token_file` or `web_identity_token` is required.",
//						Optional:    true,
//					},
//				},
//				Optional:    true,
//				Description: "An `assume_role_with_web_identity` block (documented below). Only one `assume_role_with_web_identity` block may be in the configuration.",
//			},
//			"http_proxy": schema.StringAttribute{
//				Description: "The address of an HTTP proxy to use when accessing the AWS API. Can also be configured using the `HTTP_PROXY` or `HTTPS_PROXY` environment variables.",
//				Optional:    true,
//			},
//			"insecure": schema.BoolAttribute{
//				Description: "Explicitly allow the provider to perform \"insecure\" SSL requests. If not set, defaults to `false`.",
//				Optional:    true,
//			},
//			"max_retries": schema.Int64Attribute{
//				Description: fmt.Sprintf("The maximum number of times an AWS API request is retried on failure. If not set, defaults to %d.", defaultMaxRetries),
//				Optional:    true,
//			},
//			"profile": schema.StringAttribute{
//				Description: "This is the AWS profile name as set in the shared credentials file.",
//				Optional:    true,
//			},
//			"region": schema.StringAttribute{
//				Description: "This is the AWS region. It must be provided, but it can also be sourced from the `AWS_DEFAULT_REGION` environment variables, via a shared config file, or from the EC2 Instance Metadata Service if used.",
//				Optional:    true,
//			},
//			"role_arn": schema.StringAttribute{
//				Description: "Amazon Resource Name of the AWS CloudFormation service role that is used on your behalf to perform operations.",
//				Optional:    true,
//				Validators: []validator.String{
//					validate.ARN(),
//				},
//			},
//			"secret_key": schema.StringAttribute{
//				Description: "This is the AWS secret key. It must be provided, but it can also be sourced from the `AWS_SECRET_ACCESS_KEY` environment variable, or via a shared credentials file if `profile` is specified.",
//				Optional:    true,
//			},
//			"shared_config_files": schema.ListAttribute{
//				ElementType: types.StringType,
//				Description: "List of paths to shared config files. If not set, defaults to `~/.aws/config`.",
//				Optional:    true,
//			},
//			"shared_credentials_files": schema.ListAttribute{
//				ElementType: types.StringType,
//				Description: "List of paths to shared credentials files. If not set, defaults to `~/.aws/credentials`.",
//				Optional:    true,
//			},
//			"skip_medatadata_api_check": schema.BoolAttribute{
//				Description: "Skip the AWS Metadata API check. Useful for AWS API implementations that do not have a metadata API endpoint.  Setting to `true` prevents Terraform from authenticating via the Metadata API. You may need to use other authentication methods like static credentials, configuration variables, or environment variables.",
//				Optional:    true,
//			},
//			"token": schema.StringAttribute{
//				Description: "Session token for validating temporary credentials. Typically provided after successful identity federation or Multi-Factor Authentication (MFA) login. With MFA login, this is the session token provided afterward, not the 6 digit MFA code used to get temporary credentials.  It can also be sourced from the `AWS_SESSION_TOKEN` environment variable.",
//				Optional:    true,
//			},
//			"user_agent": schema.ListNestedAttribute{
//				NestedObject: schema.NestedAttributeObject{
//					Attributes: map[string]schema.Attribute{
//						"comment": schema.StringAttribute{
//							Description: "User-Agent comment. At least one of `comment` or `product_name` must be set.",
//							Optional:    true,
//						},
//						"product_name": schema.StringAttribute{
//							Description: "Product name. At least one of `product_name` or `comment` must be set.",
//							Required:    true,
//						},
//						"product_version": schema.StringAttribute{
//							Description: "Product version. Optional, and should only be set when `product_name` is set.",
//							Optional:    true,
//						},
//					},
//				},
//				Description: "Product details to append to User-Agent string in all AWS API calls.",
//				Optional:    true,
//			},
//		},
//	}
//}
//
//type config struct {
//	AccessKey                 types.String                   `tfsdk:"access_key"`
//	HTTPProxy                 types.String                   `tfsdk:"http_proxy"`
//	Insecure                  types.Bool                     `tfsdk:"insecure"`
//	MaxRetries                types.Int64                    `tfsdk:"max_retries"`
//	Profile                   types.String                   `tfsdk:"profile"`
//	Region                    types.String                   `tfsdk:"region"`
//	RoleARN                   types.String                   `tfsdk:"role_arn"`
//	SecretKey                 types.String                   `tfsdk:"secret_key"`
//	SharedConfigFiles         types.List                     `tfsdk:"shared_config_files"`
//	SharedCredentialsFiles    types.List                     `tfsdk:"shared_credentials_files"`
//	SkipMetadataApiCheck      types.Bool                     `tfsdk:"skip_medatadata_api_check"`
//	Token                     types.String                   `tfsdk:"token"`
//	AssumeRole                *assumeRoleData                `tfsdk:"assume_role"`
//	AssumeRoleWithWebIdentity *assumeRoleWithWebIdentityData `tfsdk:"assume_role_with_web_identity"`
//	UserAgent                 []userAgentProduct             `tfsdk:"user_agent"`
//	terraformVersion          string
//}
//
//type userAgentProduct struct {
//	ProductName    types.String `tfsdk:"product_name"`
//	ProductVersion types.String `tfsdk:"product_version"`
//	Comment        types.String `tfsdk:"comment"`
//}
//
//type assumeRoleData struct {
//	RoleARN           types.String     `tfsdk:"role_arn"`
//	Duration          cctypes.Duration `tfsdk:"duration"`
//	ExternalID        types.String     `tfsdk:"external_id"`
//	Policy            types.String     `tfsdk:"policy"`
//	PolicyARNs        types.List       `tfsdk:"policy_arns"`
//	SessionName       types.String     `tfsdk:"session_name"`
//	Tags              types.Map        `tfsdk:"tags"`
//	TransitiveTagKeys types.Set        `tfsdk:"transitive_tag_keys"`
//}
//
//func (a assumeRoleData) Config() *awsbase.AssumeRole {
//	assumeRole := &awsbase.AssumeRole{
//		RoleARN:     a.RoleARN.ValueString(),
//		Duration:    a.Duration.ValueDuration(),
//		ExternalID:  a.ExternalID.ValueString(),
//		Policy:      a.Policy.ValueString(),
//		SessionName: a.SessionName.ValueString(),
//	}
//	if !a.PolicyARNs.IsNull() {
//		arns := make([]string, len(a.PolicyARNs.Elements()))
//		for i, v := range a.PolicyARNs.Elements() {
//			arns[i] = v.(types.String).ValueString()
//		}
//		assumeRole.PolicyARNs = arns
//	}
//	if !a.Tags.IsNull() {
//		tags := make(map[string]string)
//		for key, value := range a.Tags.Elements() {
//			tags[key] = value.(types.String).ValueString()
//		}
//		assumeRole.Tags = tags
//	}
//	if !a.TransitiveTagKeys.IsNull() {
//		tagKeys := make([]string, len(a.TransitiveTagKeys.Elements()))
//		for i, v := range a.TransitiveTagKeys.Elements() {
//			tagKeys[i] = v.(types.String).ValueString()
//		}
//		assumeRole.TransitiveTagKeys = tagKeys
//	}
//
//	return assumeRole
//}
//
//type assumeRoleWithWebIdentityData struct {
//	RoleARN              types.String     `tfsdk:"role_arn"`
//	Duration             cctypes.Duration `tfsdk:"duration"`
//	Policy               types.String     `tfsdk:"policy"`
//	PolicyARNs           types.List       `tfsdk:"policy_arns"`
//	SessionName          types.String     `tfsdk:"session_name"`
//	WebIdentityToken     types.String     `tfsdk:"web_identity_token"`
//	WebIdentityTokenFile types.String     `tfsdk:"web_identity_token_file"`
//}
//
//func (a assumeRoleWithWebIdentityData) Config() *awsbase.AssumeRoleWithWebIdentity {
//	assumeRole := &awsbase.AssumeRoleWithWebIdentity{
//		RoleARN:              a.RoleARN.ValueString(),
//		Duration:             a.Duration.ValueDuration(),
//		Policy:               a.Policy.ValueString(),
//		SessionName:          a.SessionName.ValueString(),
//		WebIdentityToken:     a.WebIdentityToken.ValueString(),
//		WebIdentityTokenFile: a.WebIdentityTokenFile.ValueString(),
//	}
//	if !a.PolicyARNs.IsNull() {
//		arns := make([]string, len(a.PolicyARNs.Elements()))
//		for i, v := range a.PolicyARNs.Elements() {
//			arns[i] = v.(types.String).ValueString()
//		}
//		assumeRole.PolicyARNs = arns
//	}
//
//	return assumeRole
//}
//
//func (p *ccProvider) Configure(ctx context.Context, request provider.ConfigureRequest, response *provider.ConfigureResponse) {
//	var config config
//
//	diags := request.Config.Get(ctx, &config)
//
//	if diags.HasError() {
//		response.Diagnostics.Append(diags...)
//
//		return
//	}
//
//	if !request.Config.Raw.IsFullyKnown() {
//		response.Diagnostics.AddError("Unknown Value", "An attribute value is not yet known")
//	}
//
//	config.terraformVersion = request.TerraformVersion
//
//	region, err := newCloudControlAPIClient(ctx, &config)
//
//	if err != nil {
//		response.Diagnostics.AddError(
//			"Error configuring AWS CloudControl client",
//			fmt.Sprintf("Error configuring the AWS Cloud Control API client, this is an error in the provider.\n%s\n", err),
//		)
//
//		return
//	}
//
//	providerData := &providerData{
//		region:  region,
//		roleARN: config.RoleARN.ValueString(),
//	}
//
//	p.providerData = providerData
//	response.DataSourceData = providerData
//	response.ResourceData = providerData
//}
//
//func (p *ccProvider) Resources(ctx context.Context) []func() resource.Resource {
//	var diags diag.Diagnostics
//	var resources = make([]func() resource.Resource, 0)
//
//	resourceFactories := map[string]func(ctx2 context.Context) (*resource.Resource, error){
//		"multi_account_roles": resourceDeepfenceMultiAccountReadOnlyRoles,
//	}
//
//	for name, factory := range resourceFactories {
//		v, err := factory(ctx)
//
//		if err != nil {
//			diags.AddError(
//				"Error getting Resource",
//				fmt.Sprintf("Error getting the %s Resource, this is an error in the provider.\n%s\n", name, err),
//			)
//
//			continue
//		}
//
//		resources = append(resources, func() resource.Resource {
//			return *v
//		})
//	}
//
//	return resources
//}
//
//func (p *ccProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
//	var diags diag.Diagnostics
//	dataSources := make([]func() datasource.DataSource, 0)
//
//	for name, factory := range registry.DataSourceFactories() {
//		v, err := factory(ctx)
//
//		if err != nil {
//			diags.AddError(
//				"Error getting Data Source",
//				fmt.Sprintf("Error getting the %s Data Source, this is an error in the provider.\n%s\n", name, err),
//			)
//
//			continue
//		}
//
//		dataSources = append(dataSources, func() datasource.DataSource {
//			return v
//		})
//	}
//
//	return dataSources
//}
//
//// newCloudControlAPIClient configures and returns a fully initialized AWS Cloud Control API client with the configured region.
//func newCloudControlAPIClient(ctx context.Context, pd *config) (string, error) {
//	config := awsbase.Config{
//		AccessKey:              pd.AccessKey.ValueString(),
//		CallerDocumentationURL: "https://registry.terraform.io/providers/hashicorp/awscc",
//		CallerName:             "Terraform AWS Cloud Control Provider",
//		HTTPProxy:              pd.HTTPProxy.ValueString(),
//		Insecure:               pd.Insecure.ValueBool(),
//		Profile:                pd.Profile.ValueString(),
//		Region:                 pd.Region.ValueString(),
//		SecretKey:              pd.SecretKey.ValueString(),
//		Token:                  pd.Token.ValueString(),
//		APNInfo: &awsbase.APNInfo{
//			PartnerName: "HashiCorp",
//			Products: []awsbase.UserAgentProduct{
//				{Name: "Terraform", Version: pd.terraformVersion, Comment: "+https://www.terraform.io"},
//				{Name: "terraform-provider-awscc", Version: Version, Comment: "+https://registry.terraform.io/providers/hashicorp/awscc"},
//			},
//		},
//	}
//	config.UserAgent = userAgentProducts(pd.UserAgent)
//	if pd.MaxRetries.IsNull() {
//		config.MaxRetries = defaultMaxRetries
//	} else {
//		config.MaxRetries = int(pd.MaxRetries.ValueInt64())
//	}
//	if !pd.SharedConfigFiles.IsNull() {
//		cf := make([]string, len(pd.SharedConfigFiles.Elements()))
//		for i, v := range pd.SharedConfigFiles.Elements() {
//			cf[i] = v.(types.String).ValueString()
//		}
//		config.SharedConfigFiles = cf
//	}
//	if !pd.SharedCredentialsFiles.IsNull() {
//		cf := make([]string, len(pd.SharedCredentialsFiles.Elements()))
//		for i, v := range pd.SharedCredentialsFiles.Elements() {
//			cf[i] = v.(types.String).ValueString()
//		}
//		config.SharedCredentialsFiles = cf
//	}
//	if pd.AssumeRole != nil {
//		config.AssumeRole = pd.AssumeRole.Config()
//	}
//	if pd.AssumeRoleWithWebIdentity != nil {
//		config.AssumeRoleWithWebIdentity = pd.AssumeRoleWithWebIdentity.Config()
//	}
//
//	if pd.SkipMetadataApiCheck.IsNull() {
//		config.EC2MetadataServiceEnableState = imds.ClientDefaultEnableState
//	} else if pd.SkipMetadataApiCheck.IsNull() {
//		config.EC2MetadataServiceEnableState = imds.ClientDisabled
//	} else {
//		config.EC2MetadataServiceEnableState = imds.ClientEnabled
//	}
//
//	ctx, cfg, err := awsbase.GetAwsConfig(ctx, &config)
//
//	if err != nil {
//		return "", err
//	}
//
//	return cfg.Region, nil
//}
//
//type awsSdkLogger struct{}
//type awsSdkContextLogger struct {
//	ctx context.Context
//}
//
//func (l awsSdkLogger) Logf(classification logging.Classification, format string, v ...interface{}) {
//	switch classification {
//	case logging.Warn:
//		hclog.Default().Warn("[aws-sdk-go-v2] %s", fmt.Sprintf(format, v...))
//	default:
//		hclog.Default().Debug("[aws-sdk-go-v2] %s", fmt.Sprintf(format, v...))
//	}
//}
//
//func (l awsSdkLogger) WithContext(ctx context.Context) logging.Logger {
//	return awsSdkContextLogger{ctx: ctx}
//}
//
//func (l awsSdkContextLogger) Logf(classification logging.Classification, format string, v ...interface{}) {
//	switch classification {
//	case logging.Warn:
//		tflog.Warn(l.ctx, "[aws-sdk-go-v2]", map[string]interface{}{
//			"message": hclog.Fmt(format, v...),
//		})
//	default:
//		tflog.Debug(l.ctx, "[aws-sdk-go-v2]", map[string]interface{}{
//			"message": hclog.Fmt(format, v...),
//		})
//	}
//}
//
//func userAgentProducts(products []userAgentProduct) []awsbase.UserAgentProduct {
//	results := make([]awsbase.UserAgentProduct, len(products))
//	for i, p := range products {
//		results[i] = awsbase.UserAgentProduct{
//			Name:    p.ProductName.ValueString(),
//			Version: p.ProductVersion.ValueString(),
//			Comment: p.Comment.ValueString(),
//		}
//	}
//	return results
//}
