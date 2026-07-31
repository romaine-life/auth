// OIDC relying parties that support exactly ONE identity provider.
//
// When the oauth2 authorize endpoint (Better Auth's oidcProvider plugin,
// `loginPage: "/"` in src/auth.ts) receives a signed-out user, it stashes the
// full authorize query in the signed `oidc_login_prompt` cookie and bounces
// the browser to `/?<original authorize query>` — so the landing page can see
// which relying party initiated sign-in via `client_id`. For a client listed
// here, rendering the two-provider Voight-Kampff chooser is wrong: the app
// does not accept accounts from the other provider. The landing page instead
// redirects straight into the sole supported provider's sign-in — exactly
// what clicking that provider's button would have done — and Better Auth's
// oidc-provider after-hook resumes the authorize flow the moment the
// provider's callback sets the session cookie.
//
// Already-signed-in users never reach the landing page for these flows (their
// authorize call silently issues a code off the shared `.romaine.life`
// session), so cross-subdomain SSO is untouched.
const SINGLE_PROVIDER_OIDC_CLIENTS = new Map<string, "microsoft" | "google">([
  // chess-tactics accounts are Microsoft-only; Google is not supported there.
  ["chess-tactics", "microsoft"],
]);

/** Sign-in redirect path for a signed-out landing-page visit that arrived
 *  from a single-provider OIDC client's authorize bounce. Null means the
 *  visit gets the normal provider chooser. */
export function singleProviderSignInPath(clientId: string | undefined): string | null {
  if (!clientId) return null;
  const provider = SINGLE_PROVIDER_OIDC_CLIENTS.get(clientId);
  return provider ? `/sign-in/${provider}` : null;
}
