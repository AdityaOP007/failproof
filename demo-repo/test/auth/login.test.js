import test from "node:test";
import assert from "node:assert/strict";
import { getRedirectUrl, authenticate } from "../../src/auth/login.js";

test("authenticate succeeds with correct credentials", () => {
  const user = authenticate("admin", "pass123");
  assert.ok(user);
  assert.equal(user.role, "admin");
});

test("redirect defaults to /dashboard", () => {
  const redirect = getRedirectUrl({ id: 1 }, null);
  // Expect correct path: /dashboard
  assert.equal(redirect, "/dashboard");
});
