output "resource_group_name" {
  value       = azurerm_resource_group.auth.name
  description = "Name of the auth resource group"
}

output "better_auth_secret_key_vault_id" {
  value       = azurerm_key_vault_secret.better_auth_secret.id
  description = "Key Vault secret ID for BETTER_AUTH_SECRET (sourced into k8s via ExternalSecret)"
}
