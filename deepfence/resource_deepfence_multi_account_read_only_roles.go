package deepfence

//
//import (
//	"context"
//	"github.com/hashicorp/terraform-plugin-framework/resource"
//	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
//	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
//	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
//	"strings"
//	"time"
//
//	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/client"
//	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/conns"
//	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
//)
//
//func resourceDeepfenceMultiAccountReadOnlyRoles(ctx context.Context) (*resource.Resource, error) {
//	timeout := 5 * time.Minute
//
//	attributes := map[string]schema.Attribute{
//		"arn": schema.StringAttribute{ /*START ATTRIBUTE*/
//			Description: "The ARN of the issued certificate.",
//			Computed:    true,
//			PlanModifiers: []planmodifier.String{ /*START PLAN MODIFIERS*/
//				stringplanmodifier.UseStateForUnknown(),
//			}, /*END PLAN MODIFIERS*/
//		},
//		"certificate": schema.StringAttribute{ /*START ATTRIBUTE*/
//			Description: "The issued certificate in base 64 PEM-encoded format.",
//			Computed:    true,
//			PlanModifiers: []planmodifier.String{ /*START PLAN MODIFIERS*/
//				stringplanmodifier.UseStateForUnknown(),
//			}, /*END PLAN MODIFIERS*/
//		},
//	}
//
//	attributes["id"] = schema.StringAttribute{
//		Description: "Uniquely identifies the resource.",
//		Computed:    true,
//		PlanModifiers: []planmodifier.String{
//			stringplanmodifier.UseStateForUnknown(),
//		},
//	}
//
//	schema := schema.Schema{
//		Description: "A certificate issued via a private certificate authority",
//		Version:     1,
//		Attributes:  attributes,
//	}
//
//	//return &schema.Resource{
//	//	CreateContext: resourceDeepfenceMultiAccountReadOnlyRolesCreate,
//	//	UpdateContext: resourceDeepfenceMultiAccountReadOnlyRolesUpdate,
//	//	ReadContext:   resourceDeepfenceMultiAccountReadOnlyRolesRead,
//	//	DeleteContext: resourceDeepfenceMultiAccountReadOnlyRolesDelete,
//	//	Importer: &schema.ResourceImporter{
//	//		StateContext: schema.ImportStatePassthroughContext,
//	//	},
//	//
//	//	Timeouts: &schema.ResourceTimeout{
//	//		Create: schema.DefaultTimeout(timeout),
//	//		Update: schema.DefaultTimeout(timeout),
//	//		Read:   schema.DefaultTimeout(timeout),
//	//		Delete: schema.DefaultTimeout(timeout),
//	//	},
//	//	Schema: map[string]*schema.Schema{
//	//		"account_id": {
//	//			Type:     schema.TypeString,
//	//			Required: true,
//	//		},
//	//		"cloud_provider": {
//	//			Type:         schema.TypeString,
//	//			Required:     true,
//	//			ValidateFunc: validation.StringInSlice([]string{"aws", "gcp", "azure"}, false),
//	//		},
//	//		"alias": {
//	//			Type:     schema.TypeString,
//	//			Optional: true,
//	//		},
//	//		"role_enabled": {
//	//			Type:     schema.TypeBool,
//	//			Optional: true,
//	//			Default:  false,
//	//		},
//	//		"role_name": {
//	//			Type:     schema.TypeString,
//	//			Optional: true,
//	//			Default:  "SysdigCloudBench",
//	//		},
//	//		"external_id": {
//	//			Type:     schema.TypeString,
//	//			Computed: true,
//	//		},
//	//		"workload_identity_account_id": {
//	//			Type:     schema.TypeString,
//	//			Optional: true,
//	//		},
//	//		"workload_identity_account_alias": {
//	//			Type:     schema.TypeString,
//	//			Optional: true,
//	//		},
//	//	},
//	//}
//}
//
//func resourceDeepfenceMultiAccountReadOnlyRolesCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
//	var diags diag.Diagnostics
//	conn := meta.(*conns.AWSClient).IAMConn()
//	client, err := meta.(SysdigClients).sysdigSecureClient()
//	if err != nil {
//		return diag.FromErr(err)
//	}
//
//	cloudAccount, err := client.CreateCloudAccount(ctx, cloudAccountFromResourceData(d))
//	if err != nil {
//		return diag.FromErr(err)
//	}
//
//	d.SetId(cloudAccount.AccountID)
//	_ = d.Set("account_id", cloudAccount.AccountID)
//	_ = d.Set("cloud_provider", cloudAccount.Provider)
//	_ = d.Set("alias", cloudAccount.Alias)
//	_ = d.Set("role_enabled", cloudAccount.RoleAvailable)
//	_ = d.Set("role_name", cloudAccount.RoleName)
//	_ = d.Set("external_id", cloudAccount.ExternalID)
//	_ = d.Set("workload_identity_account_id", cloudAccount.WorkLoadIdentityAccountID)
//	_ = d.Set("workload_identity_account_alias", cloudAccount.WorkLoadIdentityAccountAlias)
//
//	return nil
//}
//
//func resourceDeepfenceMultiAccountReadOnlyRolesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
//	client, err := meta.(SysdigClients).sysdigSecureClient()
//	if err != nil {
//		d.SetId("")
//		return diag.FromErr(err)
//	}
//
//	cloudAccount, err := client.GetCloudAccountById(ctx, d.Id())
//	if err != nil {
//		d.SetId("")
//		if strings.Contains(err.Error(), "404") {
//			return nil
//		}
//		return diag.FromErr(err)
//	}
//
//	_ = d.Set("account_id", cloudAccount.AccountID)
//	_ = d.Set("cloud_provider", cloudAccount.Provider)
//	_ = d.Set("alias", cloudAccount.Alias)
//	_ = d.Set("role_enabled", cloudAccount.RoleAvailable)
//	_ = d.Set("role_name", cloudAccount.RoleName)
//	_ = d.Set("external_id", cloudAccount.ExternalID)
//	_ = d.Set("workload_identity_account_id", cloudAccount.WorkLoadIdentityAccountID)
//	_ = d.Set("workload_identity_account_alias", cloudAccount.WorkLoadIdentityAccountAlias)
//
//	return nil
//}
//
//func resourceDeepfenceMultiAccountReadOnlyRolesUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
//	client, err := meta.(SysdigClients).sysdigSecureClient()
//	if err != nil {
//		return diag.FromErr(err)
//	}
//
//	_, err = client.UpdateCloudAccount(ctx, d.Id(), cloudAccountFromResourceData(d))
//	if err != nil {
//		if strings.Contains(err.Error(), "404") {
//			return nil
//		}
//		return diag.FromErr(err)
//	}
//
//	return nil
//}
//
//func resourceDeepfenceMultiAccountReadOnlyRolesDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
//	client, err := meta.(SysdigClients).sysdigSecureClient()
//	if err != nil {
//		return diag.FromErr(err)
//	}
//
//	err = client.DeleteCloudAccount(ctx, d.Id())
//	if err != nil {
//		if strings.Contains(err.Error(), "404") {
//			return nil
//		}
//		return diag.FromErr(err)
//	}
//	return nil
//}
//
//func cloudAccountFromResourceData(d *schema.ResourceData) *secure.CloudAccount {
//	return &client.CloudAccount{
//		AccountID:                    d.Get("account_id").(string),
//		Provider:                     d.Get("cloud_provider").(string),
//		Alias:                        d.Get("alias").(string),
//		RoleAvailable:                d.Get("role_enabled").(bool),
//		RoleName:                     d.Get("role_name").(string),
//		WorkLoadIdentityAccountID:    d.Get("workload_identity_account_id").(string),
//		WorkLoadIdentityAccountAlias: d.Get("workload_identity_account_alias").(string),
//	}
//}
