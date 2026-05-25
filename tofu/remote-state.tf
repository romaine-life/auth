# References to shared infrastructure provisioned by infra-bootstrap. Only
# names are stored here; full IDs are resolved via data source lookups at
# plan time so this stack doesn't have to import remote state.

locals {
  infra = {
    resource_group_name = "infra"
  }
}

data "azurerm_client_config" "current" {}

data "azurerm_user_assigned_identity" "external_secrets" {
  name                = "infra-shared-identity"
  resource_group_name = local.infra.resource_group_name
}
