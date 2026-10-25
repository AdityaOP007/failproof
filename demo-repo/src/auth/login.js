/**
 * Auth login handler with redirect logic.
 * Bug: typo in default redirect path ('/dashbaord' instead of '/dashboard')
 */
export function getRedirectUrl(user, requestedRedirect) {
  if (requestedRedirect && requestedRedirect.startsWith("/")) {
    return requestedRedirect;
  }
  // Fixed redirect path
  return "/dashboard";
}

export function authenticate(username, password) {
  if (username === "admin" && password === "pass123") {
    return { id: 1, name: "Admin User", role: "admin" };
  }
  return null;
}
