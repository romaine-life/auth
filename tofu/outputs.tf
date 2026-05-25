output "resource_group_name" {
  value       = azurerm_resource_group.auth.name
  description = "Name of the auth resource group"
}

output "better_auth_secret_key_vault_id" {
  value       = azurerm_key_vault_secret.better_auth_secret_app.id
  description = "Auth-owned Key Vault secret ID for BETTER_AUTH_SECRET (sourced into k8s via ExternalSecret)"
}

output "auth_db_backups_storage_account" {
  value       = azurerm_storage_account.auth_db_backups.name
  description = "Storage account holding auth-db CNPG backups. Drives the destinationPath in cluster.yaml."
}

output "auth_db_backups_container" {
  value       = azurerm_storage_container.auth_db_backups.name
  description = "Container within the backups storage account."
}

output "auth_db_backup_writer_client_id" {
  value       = azurerm_user_assigned_identity.auth_db_backup_writer.client_id
  description = "Client ID of the UAMI federated to the auth-db ServiceAccount. After this stack applies, copy into k8s/values.yaml backups.workloadIdentityClientId in the chart-side cutover PR."
}
