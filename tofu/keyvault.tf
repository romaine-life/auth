resource "azurerm_key_vault" "main" {
  name                       = var.key_vault_name
  resource_group_name        = azurerm_resource_group.auth.name
  location                   = azurerm_resource_group.auth.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  soft_delete_retention_days = 7

  tags = {
    app       = "auth"
    managedBy = "auth"
    purpose   = "app-secrets"
  }
}

resource "azurerm_role_assignment" "external_secrets_keyvault" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = data.azurerm_user_assigned_identity.external_secrets.principal_id
}

# Better Auth's signing secret. Used for session cookie crypto and as a
# fallback for any module that needs symmetric signing inside Better Auth.
# (JWTs issued to apps are signed with the RSA key Better Auth manages in
# its own DB table; that's separate from this secret.)
resource "random_password" "better_auth_secret" {
  length  = 64
  special = false
}

resource "azurerm_key_vault_secret" "better_auth_secret_app" {
  name         = "auth-better-auth-secret"
  value        = random_password.better_auth_secret.result
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [
    azurerm_role_assignment.external_secrets_keyvault,
  ]
}
