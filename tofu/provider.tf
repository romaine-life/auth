# Remote state in Azure Storage (backend config passed via -backend-config in CI).
# OIDC auth for the Azure providers — no static credentials stored.

# The providers and their versions are pinned in versions.tf and .terraform.lock.hcl.

terraform {
  backend "azurerm" {}
}

provider "azurerm" {
  features {}
  use_oidc = true
}
