export function adminLoginRedirectPath(requestURL: string): string {
  const url = new URL(requestURL);
  const callbackURL = `${url.pathname}${url.search}`;
  return `/sign-in/microsoft?callbackURL=${encodeURIComponent(callbackURL || "/admin")}`;
}
