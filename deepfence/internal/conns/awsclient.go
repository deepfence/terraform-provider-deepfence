package conns

import (
	"context"
	"github.com/aws/aws-sdk-go/service/mediaconvert"
	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/experimental/intf"
	tftags "github.com/deepfence/terraform-provider-deepfence/deepfence/internal/tags"
	"net/http"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

type AWSClient struct {
	AccountID               string
	DefaultTagsConfig       *tftags.DefaultConfig
	DNSSuffix               string
	IgnoreTagsConfig        *tftags.IgnoreConfig
	MediaConvertAccountConn *mediaconvert.MediaConvert
	Partition               string
	Region                  string
	ReverseDNSPrefix        string
	ServicePackages         []intf.ServicePackage
	Session                 *session.Session
	TerraformVersion        string

	httpClient *http.Client

	iamConn *iam.IAM
	//stsConn *sts.STS
}

func (client *AWSClient) InitContext(ctx context.Context) context.Context {
	return ctx
}

func (client *AWSClient) IAMConn() *iam.IAM {
	return client.iamConn
}

//	func (client *AWSClient) STSConn() *sts.STS {
//		return client.stsConn
//	}
func (client *AWSClient) SetHTTPClient(httpClient *http.Client) {
	if client.Session == nil {
		client.httpClient = httpClient
	}
}

func (client *AWSClient) HTTPClient() *http.Client {
	return client.httpClient
}
