package iam

import (
	"context"
	"fmt"
	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	"log"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/conns"
	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/errs/sdkdiag"
	tftags "github.com/deepfence/terraform-provider-deepfence/deepfence/internal/tags"
	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/tfresource"
	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/verify"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/structure"
)

func ResourceMultiAccountReadOnly() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceMultiAccountReadOnlyCreate,
		ReadWithoutTimeout:   resourceMultiAccountReadOnlyRead,
		UpdateWithoutTimeout: resourceMultiAccountReadOnlyUpdate,
		DeleteWithoutTimeout: resourceMultiAccountReadOnlyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"description": {
				Type:     schema.TypeString,
				ForceNew: true,
				Optional: true,
			},
			"path": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "/",
				ForceNew: true,
			},
			"policy": {
				Type:                  schema.TypeString,
				Required:              true,
				ValidateFunc:          verify.ValidIAMPolicyJSON,
				DiffSuppressFunc:      verify.SuppressEquivalentPolicyDiffs,
				DiffSuppressOnRefresh: true,
				StateFunc: func(v interface{}) string {
					json, _ := structure.NormalizeJsonString(v)
					return json
				},
			},
			"name": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name_prefix"},
				ValidateFunc:  validResourceName(policyNameMaxLen),
			},
			"name_prefix": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name"},
				ValidateFunc:  validResourceName(policyNamePrefixMaxLen),
			},
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"policy_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tags":     tftags.TagsSchema(),
			"tags_all": tftags.TagsSchemaComputed(),
		},

		CustomizeDiff: verify.SetTagsDiff,
	}
}

func resourceMultiAccountReadOnlyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	var accountIds []string
	var productName string
	var cloudScannerMemberAccountId string
	if v, ok := d.GetOk("account_ids"); ok {
		accountIds = v.([]string)
	}
	roleArns := make([]string, len(accountIds))
	if v, ok := d.GetOk("product_name"); ok {
		productName = v.(string)
	}
	if v, ok := d.GetOk("product_name"); ok {
		cloudScannerMemberAccountId = v.(string)
	}
	for _, accountId := range accountIds {
		accountAssumeRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/OrganizationAccountAccessRole", accountId)
		config := conns.Config{
			AccessKey:                      d.Get("access_key").(string),
			CustomCABundle:                 d.Get("custom_ca_bundle").(string),
			EC2MetadataServiceEndpoint:     d.Get("ec2_metadata_service_endpoint").(string),
			EC2MetadataServiceEndpointMode: d.Get("ec2_metadata_service_endpoint_mode").(string),
			Endpoints:                      make(map[string]string),
			HTTPProxy:                      d.Get("http_proxy").(string),
			Insecure:                       d.Get("insecure").(bool),
			MaxRetries:                     25, // Set default here, not in schema (muxing with v6 provider).
			Profile:                        d.Get("profile").(string),
			Region:                         d.Get("region").(string),
			S3UsePathStyle:                 d.Get("s3_use_path_style").(bool) || d.Get("s3_force_path_style").(bool),
			SecretKey:                      d.Get("secret_key").(string),
			SkipCredsValidation:            d.Get("skip_credentials_validation").(bool),
			SkipGetEC2Platforms:            d.Get("skip_get_ec2_platforms").(bool),
			SkipRegionValidation:           d.Get("skip_region_validation").(bool),
			SkipRequestingAccountId:        d.Get("skip_requesting_account_id").(bool),
			STSRegion:                      d.Get("sts_region").(string),
			TerraformVersion:               "",
			Token:                          d.Get("token").(string),
			UseDualStackEndpoint:           d.Get("use_dualstack_endpoint").(bool),
			UseFIPSEndpoint:                d.Get("use_fips_endpoint").(bool),
		}
		config.AssumeRole = &awsbase.AssumeRole{RoleARN: accountAssumeRoleArn}

		var metaClient *conns.AWSClient
		if v, ok := meta.(*conns.AWSClient); ok {
			metaClient = v
		} else {
			metaClient = new(conns.AWSClient)
		}
		metaClient, diagns := config.ConfigureProvider(ctx, metaClient)
		if diagns.HasError() {
			sdkdiag.AppendErrorf(diags, "Unable to configure provider in account %s: %s", accountId, diagns)
		}

		assumeRolePolicyDoc := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::%s:role/%s-organizational-ECSTaskRole"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`, cloudScannerMemberAccountId, productName)

		iamConn := metaClient.IAMConn()

		roleName := fmt.Sprintf("%s-mem-acc-read-only-access", productName)

		createdRoleOutput, err := iamConn.CreateRoleWithContext(ctx, &iam.CreateRoleInput{RoleName: &roleName,
			AssumeRolePolicyDocument: &assumeRolePolicyDoc})
		if err != nil {
			sdkdiag.AppendErrorf(diags, "Unable to create role in account %s: %s", accountId, err)
		}

		readOnlyPolicyArn := "arn:aws:iam::aws:policy/ReadOnlyAccess"
		managedReadOnlyPolicyOutput, err := iamConn.GetPolicyWithContext(ctx,
			&iam.GetPolicyInput{PolicyArn: &readOnlyPolicyArn})
		if err != nil {
			sdkdiag.AppendErrorf(diags, "Unable to get read only policy in account %s: %s", accountId, err)
		}
		if *managedReadOnlyPolicyOutput.Policy.Arn == "" {
			sdkdiag.AppendErrorf(diags, "Unable to fetch read only policy in account %s: %s", accountId, err)
		}

		_, err = iamConn.AttachRolePolicyWithContext(ctx, &iam.AttachRolePolicyInput{
			PolicyArn: managedReadOnlyPolicyOutput.Policy.Arn, RoleName: createdRoleOutput.Role.RoleName})
		if err != nil {
			sdkdiag.AppendErrorf(diags, "Unable to attach policy to role in account %s: %s", accountId)
		}
		roleArns = append(roleArns, *createdRoleOutput.Role.Arn)
	}
	if len(diags) > 0 {
		return diags
	}

	//conn := meta.(*conns.AWSClient).IAMConn()
	//defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	//tags := defaultTagsConfig.MergeTags(tftags.New(d.Get("tags").(map[string]interface{})))
	//
	//var name string
	//if v, ok := d.GetOk("name"); ok {
	//	name = v.(string)
	//} else if v, ok := d.GetOk("name_prefix"); ok {
	//	name = resource.PrefixedUniqueId(v.(string))
	//} else {
	//	name = resource.UniqueId()
	//}
	//
	//policy, err := structure.NormalizeJsonString(d.Get("policy").(string))
	//if err != nil {
	//	return sdkdiag.AppendErrorf(diags, "policy (%s) is invalid JSON: %s", policy, err)
	//}
	//
	//request := &iam.CreatePolicyInput{
	//	Description:    aws.String(d.Get("description").(string)),
	//	Path:           aws.String(d.Get("path").(string)),
	//	PolicyDocument: aws.String(policy),
	//	PolicyName:     aws.String(name),
	//}
	//
	//if len(tags) > 0 {
	//	request.Tags = Tags(tags.IgnoreAWS())
	//}
	//
	//response, err := conn.CreatePolicyWithContext(ctx, request)
	//
	//// Some partitions (i.e., ISO) may not support tag-on-create
	//if request.Tags != nil && verify.ErrorISOUnsupported(conn.PartitionID, err) {
	//	log.Printf("[WARN] failed creating IAM Policy (%s) with tags: %s. Trying create without tags.", name, err)
	//	request.Tags = nil
	//
	//	response, err = conn.CreatePolicyWithContext(ctx, request)
	//}
	//
	//if err != nil {
	//	return sdkdiag.AppendErrorf(diags, "creating IAM Policy %s: %s", name, err)
	//}

	roleArnsString := strings.Join(roleArns, ",")
	d.SetId(aws.StringValue(&roleArnsString))

	//// Some partitions (i.e., ISO) may not support tag-on-create, attempt tag after create
	//if request.Tags == nil && len(tags) > 0 {
	//	err := policyUpdateTags(ctx, conn, d.Id(), nil, tags)
	//
	//	// If default tags only, log and continue. Otherwise, error.
	//	if v, ok := d.GetOk("tags"); (!ok || len(v.(map[string]interface{})) == 0) && verify.ErrorISOUnsupported(conn.PartitionID, err) {
	//		log.Printf("[WARN] failed adding tags after create for IAM Policy (%s): %s", d.Id(), err)
	//		return append(diags, resourceMultiAccountReadOnlyRead(ctx, d, meta)...)
	//	}
	//
	//	if err != nil {
	//		return sdkdiag.AppendErrorf(diags, "adding tags after create for IAM Policy (%s): %s", d.Id(), err)
	//	}
	//}

	return append(diags, resourceMultiAccountReadOnlyRead(ctx, d, meta)...)
}

func resourceMultiAccountReadOnlyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IAMConn()
	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	ignoreTagsConfig := meta.(*conns.AWSClient).IgnoreTagsConfig

	input := &iam.GetPolicyInput{
		PolicyArn: aws.String(d.Id()),
	}

	// Handle IAM eventual consistency
	var getPolicyResponse *iam.GetPolicyOutput
	err := resource.RetryContext(ctx, propagationTimeout, func() *resource.RetryError {
		var err error
		getPolicyResponse, err = conn.GetPolicyWithContext(ctx, input)

		if d.IsNewResource() && tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
			return resource.RetryableError(err)
		}

		if err != nil {
			return resource.NonRetryableError(err)
		}

		return nil
	})

	if tfresource.TimedOut(err) {
		getPolicyResponse, err = conn.GetPolicyWithContext(ctx, input)
	}

	if !d.IsNewResource() && tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
		log.Printf("[WARN] IAM Policy (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading IAM policy %s: %s", d.Id(), err)
	}

	if !d.IsNewResource() && (getPolicyResponse == nil || getPolicyResponse.Policy == nil) {
		log.Printf("[WARN] IAM Policy (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	policy := getPolicyResponse.Policy

	d.Set("arn", policy.Arn)
	d.Set("description", policy.Description)
	d.Set("name", policy.PolicyName)
	d.Set("path", policy.Path)
	d.Set("policy_id", policy.PolicyId)

	tags := KeyValueTags(policy.Tags).IgnoreAWS().IgnoreConfig(ignoreTagsConfig)

	//lintignore:AWSR002
	if err := d.Set("tags", tags.RemoveDefaultConfig(defaultTagsConfig).Map()); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting tags: %s", err)
	}

	if err := d.Set("tags_all", tags.Map()); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting tags_all: %s", err)
	}

	// Retrieve policy

	getPolicyVersionRequest := &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(d.Id()),
		VersionId: policy.DefaultVersionId,
	}

	// Handle IAM eventual consistency
	var getPolicyVersionResponse *iam.GetPolicyVersionOutput
	err = resource.RetryContext(ctx, propagationTimeout, func() *resource.RetryError {
		var err error
		getPolicyVersionResponse, err = conn.GetPolicyVersionWithContext(ctx, getPolicyVersionRequest)

		if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
			return resource.RetryableError(err)
		}

		if err != nil {
			return resource.NonRetryableError(err)
		}

		return nil
	})

	if tfresource.TimedOut(err) {
		getPolicyVersionResponse, err = conn.GetPolicyVersionWithContext(ctx, getPolicyVersionRequest)
	}

	if !d.IsNewResource() && tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
		log.Printf("[WARN] IAM Policy (%s) version (%s) not found, removing from state", d.Id(), aws.StringValue(policy.DefaultVersionId))
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading IAM policy version %s: %s", d.Id(), err)
	}

	var policyDocument string
	if getPolicyVersionResponse != nil && getPolicyVersionResponse.PolicyVersion != nil {
		var err error
		policyDocument, err = url.QueryUnescape(aws.StringValue(getPolicyVersionResponse.PolicyVersion.Document))
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "parsing IAM policy (%s) document: %s", d.Id(), err)
		}
	}

	policyToSet, err := verify.PolicyToSet(d.Get("policy").(string), policyDocument)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "while setting policy (%s), encountered: %s", policyToSet, err)
	}

	d.Set("policy", policyToSet)

	return diags
}

func resourceMultiAccountReadOnlyUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IAMConn()

	if d.HasChangesExcept("tags", "tags_all") {
		if err := policyPruneVersions(ctx, d.Id(), conn); err != nil {
			return sdkdiag.AppendErrorf(diags, "updating IAM policy %s: pruning versions: %s", d.Id(), err)
		}

		policy, err := structure.NormalizeJsonString(d.Get("policy").(string))
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "policy (%s) is invalid JSON: %s", policy, err)
		}

		request := &iam.CreatePolicyVersionInput{
			PolicyArn:      aws.String(d.Id()),
			PolicyDocument: aws.String(policy),
			SetAsDefault:   aws.Bool(true),
		}

		if _, err := conn.CreatePolicyVersionWithContext(ctx, request); err != nil {
			return sdkdiag.AppendErrorf(diags, "updating IAM policy %s: %s", d.Id(), err)
		}
	}

	if d.HasChange("tags_all") {
		o, n := d.GetChange("tags_all")

		err := policyUpdateTags(ctx, conn, d.Id(), o, n)

		// Some partitions (i.e., ISO) may not support tagging, giving error
		if verify.ErrorISOUnsupported(conn.PartitionID, err) {
			log.Printf("[WARN] failed updating tags for IAM Policy (%s): %s", d.Id(), err)
			return append(diags, resourceMultiAccountReadOnlyRead(ctx, d, meta)...)
		}

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating tags for IAM Policy (%s): %s", d.Id(), err)
		}
	}

	return append(diags, resourceMultiAccountReadOnlyRead(ctx, d, meta)...)
}

func resourceMultiAccountReadOnlyDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IAMConn()

	if err := policyDeleteNonDefaultVersions(ctx, d.Id(), conn); err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting IAM policy (%s): deleting non-default versions: %s", d.Id(), err)
	}

	request := &iam.DeletePolicyInput{
		PolicyArn: aws.String(d.Id()),
	}

	_, err := conn.DeletePolicyWithContext(ctx, request)

	if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting IAM policy (%s): %s", d.Id(), err)
	}

	return diags
}
