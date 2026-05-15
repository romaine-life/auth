# Better Auth's signing secret. Used for session cookie crypto and as a
# fallback for any module that needs symmetric signing inside Better Auth.
# (JWTs issued to apps are signed with the RSA key Better Auth manages in
# its own DB table; that's separate from this secret.) The shared identity
# already has Key Vault Secrets User on the whole vault, so external-secrets
# can pull this into the auth namespace via ExternalSecret.
resource "random_password" "better_auth_secret" {
  length  = 64
  special = false
}

resource "azurerm_key_vault_secret" "better_auth_secret" {
  name         = "auth-better-auth-secret"
  value        = random_password.better_auth_secret.result
  key_vault_id = data.azurerm_key_vault.main.id
}
