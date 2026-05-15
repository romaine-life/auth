resource "azurerm_resource_group" "auth" {
  name     = "auth-rg"
  location = var.location
}
