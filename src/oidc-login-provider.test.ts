import { test } from "node:test";
import assert from "node:assert/strict";
import {
  landingSignInRedirect,
  signedOAuthQuery,
  singleProviderSignInPath,
} from "./oidc-login-provider.js";

// A real authorize bounce, captured from the deployed provider: the query the
// browser is handed when a signed-out Chess Tactics user presses Sign in.
const AUTHORIZE_BOUNCE = "response_type=code&client_id=chess-tactics"
  + "&redirect_uri=https%3A%2F%2Fchess-tactics.com%2Fapi%2Fauth%2Fcallback"
  + "&scope=openid+profile+email+offline_access&state=probe789"
  + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
  + "&nonce=probe789&exp=1786656220&ba_iat=1786655620536"
  + "&ba_param=ba_iat&ba_param=ba_param&ba_param=client_id&ba_param=code_challenge"
  + "&ba_param=code_challenge_method&ba_param=exp&ba_param=nonce&ba_param=redirect_uri"
  + "&ba_param=response_type&ba_param=scope&ba_param=state"
  + "&sig=M4GiLntEwvBsOBsFmY2YTc8EHfOoD50d3ErHyGQ2wZc%3D";

test("chess-tactics authorize bounce goes straight to Microsoft sign-in", () => {
  assert.equal(singleProviderSignInPath("chess-tactics"), "/sign-in/microsoft");
});

test("clients that support both providers keep the chooser", () => {
  assert.equal(singleProviderSignInPath("grafana"), null);
  assert.equal(singleProviderSignInPath("argocd"), null);
  assert.equal(singleProviderSignInPath("ambience"), null);
});

test("a plain landing-page visit (no client_id) keeps the chooser", () => {
  assert.equal(singleProviderSignInPath(undefined), null);
  assert.equal(singleProviderSignInPath(""), null);
});

test("inherited Object.prototype names never force a provider", () => {
  assert.equal(singleProviderSignInPath("toString"), null);
  assert.equal(singleProviderSignInPath("constructor"), null);
});

test("a real authorize bounce survives intact", () => {
  // Every parameter the provider sent is one it signed, so the whole query
  // comes back — this is the string the sign-in call must carry as
  // `oauth_query` for the flow to resume.
  assert.equal(signedOAuthQuery(`?${AUTHORIZE_BOUNCE}`), AUTHORIZE_BOUNCE);
});

test("only the parameters ba_param names are carried", () => {
  // Anything outside the signature would make verification fail, so a query
  // that picked up extra parameters still yields exactly what was signed.
  assert.equal(
    signedOAuthQuery("?client_id=grafana&utm_source=email&ba_param=client_id&ba_param=ba_param&sig=abc"),
    "client_id=grafana&ba_param=client_id&ba_param=ba_param&sig=abc",
  );
});

test("an ordinary visit carries no authorization request", () => {
  assert.equal(signedOAuthQuery(""), null);
  assert.equal(signedOAuthQuery("?client_id=chess-tactics"), null);
  // A signature with nothing declaring what it covers is unusable.
  assert.equal(signedOAuthQuery("?client_id=chess-tactics&sig=abc"), null);
  // As is a declaration with no signature.
  assert.equal(signedOAuthQuery("?client_id=chess-tactics&ba_param=client_id"), null);
});

test("the single-provider redirect carries the pending authorization", () => {
  const redirect = landingSignInRedirect(`?${AUTHORIZE_BOUNCE}`, "chess-tactics");
  assert.ok(redirect, "a single-provider client must be redirected");
  const [path, query] = redirect.split("?");
  assert.equal(path, "/sign-in/microsoft");
  // Dropping this is the defect: the provider sets no cookie on the bounce, so
  // a bare /sign-in/microsoft loses the relying party's request outright.
  assert.equal(new URLSearchParams(query).get("oauth_query"), AUTHORIZE_BOUNCE);
});

test("a single-provider sign-in with nothing pending stays a bare path", () => {
  assert.equal(landingSignInRedirect("", "chess-tactics"), "/sign-in/microsoft");
});

test("a chooser client is not redirected, pending request or not", () => {
  assert.equal(landingSignInRedirect(`?${AUTHORIZE_BOUNCE}`, "grafana"), null);
  assert.equal(landingSignInRedirect("", undefined), null);
});
