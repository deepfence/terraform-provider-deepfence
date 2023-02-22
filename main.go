package main

import (
	"github.com/deepfence/terraform-provider-deepfence/deepfence"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{ProviderFunc: deepfence.New})
}
