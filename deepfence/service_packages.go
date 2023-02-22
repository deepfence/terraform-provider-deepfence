package deepfence

import (
	"context"
	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/experimental/intf"
	"github.com/deepfence/terraform-provider-deepfence/deepfence/internal/service/iam"
	"golang.org/x/exp/slices"
)

func servicePackages(context.Context) []intf.ServicePackage {
	v := []intf.ServicePackage{
		iam.ServicePackage,
	}
	return slices.Clone(v)
}
