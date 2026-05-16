# Backup destination for the auth-db CNPG Cluster. CloudNativePG's
# barmanObjectStore handles continuous WAL archiving and periodic base
# backups; the destination here is a dedicated Azure Storage Account
# scoped to one container so a compromised connection string can't reach
# any other workload's data.
#
# Auth model: account access key, stored in KV, mirrored into the auth
# namespace via ExternalSecret. Workload-identity-based access would be
# tighter (no symmetric secret in cluster) but CNPG's
# inheritFromAzureAD path is more complex to wire and the storage
# account is single-purpose. If a future hardening pass migrates to
# workload identity, the migration plan is documented in
# k8s/templates/cluster.yaml.

# Storage account name must be globally unique, lowercase alphanumeric,
# 3-24 chars. random_string suffix keeps it deterministic per state
# file while avoiding collisions across environments.
resource "random_string" "backups_suffix" {
  length  = 6
  upper   = false
  special = false
  numeric = true
}

resource "azurerm_storage_account" "auth_db_backups" {
  name                = "authdbbackups${random_string.backups_suffix.result}"
  resource_group_name = azurerm_resource_group.auth.name
  location            = azurerm_resource_group.auth.location

  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  # Storage account-level public access can stay enabled; the container
  # below is configured private so blobs require auth.
  public_network_access_enabled   = true
  allow_nested_items_to_be_public = false

  # TLS 1.2 minimum is the current Azure default for new accounts but
  # pinning it explicitly defends against a future provider default
  # weakening.
  min_tls_version = "TLS1_2"

  # Soft-delete keeps deleted blobs/containers around for 30 days so an
  # accidental delete (CNPG bug, mis-typed retention policy) is
  # recoverable. Cheap insurance — costs storage for the soft-deleted
  # period only.
  blob_properties {
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
}

resource "azurerm_storage_container" "auth_db_backups" {
  name                  = "auth-db"
  storage_account_id    = azurerm_storage_account.auth_db_backups.id
  container_access_type = "private"
}

# CNPG reads the storage account connection string from a Kubernetes
# Secret. The connection string carries the account access key, so it
# grants full account access — fine here because this account is
# single-purpose (only this CNPG cluster's backups land in it).
#
# The k8s Secret is provisioned by external-secrets-operator from this
# KV entry via the ExternalSecret in k8s/templates/.
resource "azurerm_key_vault_secret" "auth_db_backup_connection_string" {
  name         = "auth-db-backup-storage-connection"
  value        = azurerm_storage_account.auth_db_backups.primary_connection_string
  key_vault_id = data.azurerm_key_vault.main.id
}
