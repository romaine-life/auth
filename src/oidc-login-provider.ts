// The landing page's half of the OAuth authorization flow.
//
// When the oauth2 authorize endpoint (`loginPage: "/"` in src/auth.ts) receives
// a signed-out user, it bounces the browser to `/?<the authorize query>` with
// the whole pending request signed into that query — `sig`, plus a `ba_param`
// entry naming each parameter the signature covers. That query is the ONLY
// carrier: `@better-auth/oauth-provider` sets no cookie on the bounce, so a
// landing page that redirects or submits without it has dropped the
// authorization request, and the user completes a provider login only to land
// back here with the relying party still waiting for a code.
//
// The provider resumes the flow when a sign-in call carries that query as
// `oauth_query` in its body: a before-hook verifies the signature and threads
// the request through the provider round trip in the OAuth state row, and an
// after-hook re-enters authorize the moment the provider's callback sets the
// session cookie. That is the documented integration for a custom sign-in
// endpoint, which every route in src/server.ts is.
//
// This used to need no cooperation at all — the predecessor `oidcProvider`
// plugin stashed the request in an `oidc_login_prompt` cookie and resumed off
// that. Migrating to `@better-auth/oauth-provider` removed the cookie and left
// this page discarding the query, which broke sign-in for every relying party
// whose user did not already hold a `.romaine.life` session.
//
// Already-signed-in users never reach this page for these flows (their
// authorize call silently issues a code off the shared session), so
// cross-subdomain SSO was — and is — untouched.

// OIDC relying parties that support exactly ONE identity provider. For a client
// listed here, rendering the two-provider Voight-Kampff chooser is wrong: the
// app does not accept accounts from the other provider, so the landing page
// goes straight into the sole supported provider's sign-in — exactly what
// clicking that provider's button would have done.
const SINGLE_PROVIDER_OIDC_CLIENTS = new Map<string, "microsoft" | "google">([
  // chess-tactics accounts are Microsoft-only; Google is not supported there.
  ["chess-tactics", "microsoft"],
]);

// The parameter the provider repeats once per signed parameter name. Anything
// not named by it is outside the signature and must not be forwarded.
const SIGNED_PARAMETER_NAMES = "ba_param";

/** Sign-in redirect path for a signed-out landing-page visit that arrived
 *  from a single-provider OIDC client's authorize bounce. Null means the
 *  visit gets the normal provider chooser. */
export function singleProviderSignInPath(clientId: string | undefined): string | null {
  if (!clientId) return null;
  const provider = SINGLE_PROVIDER_OIDC_CLIENTS.get(clientId);
  return provider ? `/sign-in/${provider}` : null;
}

/**
 * The signed authorize request carried by a landing-page URL, or null when the
 * visit is an ordinary one with no authorization pending.
 *
 * Only the parameters `ba_param` names are kept, so a link that arrives with
 * extra query junk still yields the exact string the signature was computed
 * over. Mirrors `buildSignedOAuthQuery`, which the provider package exports
 * only into its browser client bundle.
 */
export function signedOAuthQuery(search: string): string | null {
  const params = new URLSearchParams(search);
  if (!params.has("sig")) return null;
  const signedNames = new Set(params.getAll(SIGNED_PARAMETER_NAMES));
  if (!signedNames.size) return null;
  const signed = new URLSearchParams();
  for (const [name, value] of params) {
    if (name === "sig" || name === SIGNED_PARAMETER_NAMES || signedNames.has(name)) {
      signed.append(name, value);
    }
  }
  return signed.toString();
}

/**
 * Where a signed-out landing-page visit goes before the page is rendered, or
 * null to render the provider chooser.
 *
 * The pending authorization request rides along as `oauth_query`; dropping it
 * here is the whole bug this function exists to make impossible to reintroduce
 * silently.
 */
export function landingSignInRedirect(search: string, clientId: string | undefined): string | null {
  const path = singleProviderSignInPath(clientId);
  if (!path) return null;
  const oauthQuery = signedOAuthQuery(search);
  return oauthQuery ? `${path}?oauth_query=${encodeURIComponent(oauthQuery)}` : path;
}
