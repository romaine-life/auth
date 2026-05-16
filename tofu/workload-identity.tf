# Workload-identity infrastructure for the auth-db CNPG cluster's
# backup writes. Replaces the connection-string auth flow:
#   - Previously: storage account access key in KV -> ExternalSecret ->
#     k8s Secret -> CNPG barmanObjectStore.azureCredentials.connectionString
#   - Now (after the chart-side cutover): federated UAMI -> projected
#     SA token -> Storage Blob Data Contributor on the backup container.
#
# The connection-string path stays live until the chart-side PR flips
# CNPG to inheritFromAzureAD. This file only provisions the Azure side;
# the chart still uses the connection string today.

# Dedicated UAMI for CNPG backup writes. Scope is minimal:
# Storage Blob Data Contributor on the single container that holds
# auth-db backups.
resource "azurerm_user_assigned_identity" "auth_db_backup_writer" {
  name                = "auth-db-backup-writer"
  resource_group_name = azurerm_resource_group.auth.name
  location            = azurerm_resource_group.auth.location
}

# Federated credential trusts tokens issued by the AKS OIDC issuer for
# the auth-db ServiceAccount. CNPG creates the SA named after the
# Cluster ("auth-db"); kubectl get sa -n auth confirms.
resource "azurerm_federated_identity_credential" "auth_db_backup_writer" {
  name                = "auth-db"
  resource_group_name = azurerm_resource_group.auth.name
  parent_id           = azurerm_user_assigned_identity.auth_db_backup_writer.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = var.aks_oidc_issuer_url
  subject             = "system:serviceaccount:auth:auth-db"
}

# Storage Blob Data Contributor at container scope (NOT account scope)
# so a compromised pod can't reach into other workloads' blobs in the
# same account.
resource "azurerm_role_assignment" "auth_db_backup_writer_blob_contributor" {
  scope                = azurerm_storage_container.auth_db_backups.resource_manager_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.auth_db_backup_writer.principal_id
}
