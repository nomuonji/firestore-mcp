import test from "node:test";
import assert from "node:assert/strict";
import {
  basicOwnerAuthorizationMatches,
  parseOAuthScopes,
  pkceChallenge,
  safeOAuthRedirect,
  signOAuthToken,
  verifyOAuthToken
} from "../src/oauth.js";

const secret = "test-owner-token-0123456789-abcdefghijklmnopqrstuvwxyz";

test("signs and validates stateless OAuth tokens with expiry and token kind", async () => {
  const now = Date.UTC(2026, 10, 9, 0, 0, 0);
  const token = await signOAuthToken("access", { clientId: "chatgpt", scope: "firestore:access", aud: "https://example.com/mcp" }, secret, now);
  const decoded = await verifyOAuthToken(token, "access", secret, now + 1000);
  assert.equal(decoded?.clientId, "chatgpt");
  assert.equal(decoded?.aud, "https://example.com/mcp");
  assert.equal(await verifyOAuthToken(token, "refresh", secret, now + 1000), null);
  assert.equal(await verifyOAuthToken(token, "access", "a-different-secret-long-enough-to-be-valid", now + 1000), null);
  assert.equal(await verifyOAuthToken(token, "access", secret, now + 61 * 60 * 1000), null);
});

test("binds authorization codes to the PKCE S256 verifier", async () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  assert.equal(await pkceChallenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  const now = Date.UTC(2026, 10, 9, 0, 0, 0);
  const code = await signOAuthToken("code", { challenge: await pkceChallenge(verifier) }, secret, now);
  const decoded = await verifyOAuthToken(code, "code", secret, now + 1000);
  assert.equal(decoded?.challenge, await pkceChallenge(verifier));
  assert.notEqual(await pkceChallenge("a-different-verifier"), await pkceChallenge(verifier));
});

test("rejects OAuth token tampering and redirects outside ChatGPT", async () => {
  const token = await signOAuthToken("access", { aud: "https://example.com/mcp" }, secret);
  const [body, signature] = token.split(".");
  const changedSignature = (signature?.[0] === "A" ? "B" : "A") + (signature?.slice(1) ?? "");
  assert.equal(await verifyOAuthToken(body + "." + changedSignature, "access", secret), null);
  assert.equal(safeOAuthRedirect("https://chatgpt.com/connector/oauth/callback")?.hostname, "chatgpt.com");
  assert.equal(safeOAuthRedirect("https://claude.ai/api/mcp/auth_callback")?.hostname, "claude.ai");
  assert.equal(safeOAuthRedirect("https://claude.ai/other"), null);
  assert.equal(safeOAuthRedirect("https://evil.claude.ai/api/mcp/auth_callback"), null);
  assert.equal(safeOAuthRedirect("https://evil.example/steal"), null);
  assert.equal(safeOAuthRedirect("javascript:alert(1)"), null);
});

test("accepts only supported Firestore OAuth scopes", () => {
  assert.deepEqual(parseOAuthScopes("firestore:access offline_access"), ["firestore:access", "offline_access"]);
  assert.deepEqual(parseOAuthScopes(""), ["firestore:access", "offline_access"]);
  assert.throws(() => parseOAuthScopes("admin"));
  assert.throws(() => parseOAuthScopes("offline_access"));
});

test("supports a non-empty plain-text owner key such as the configured dashboard variable", async () => {
  const ownerKey = "short-owner-password";
  const token = await signOAuthToken("access", {
    clientId: "chatgpt",
    scope: "firestore:access",
    aud: "https://example.com/mcp"
  }, ownerKey);
  const verified = await verifyOAuthToken(token, "access", ownerKey);
  assert.equal(verified?.clientId, "chatgpt");
  assert.equal(await verifyOAuthToken(token, "access", "incorrect"), null);
  await assert.rejects(() => signOAuthToken("access", {}, ""), /must not be empty/);
});

test("authenticates the owner through HTTP Basic without putting the key in a form or URL", () => {
  const ownerPassword = "short-owner-password";
  const valid = "Basic " + btoa("owner:" + ownerPassword);
  assert.equal(basicOwnerAuthorizationMatches(valid, ownerPassword), true);
  assert.equal(basicOwnerAuthorizationMatches("Basic " + btoa("other:" + ownerPassword), ownerPassword), false);
  assert.equal(basicOwnerAuthorizationMatches("Basic " + btoa("owner:wrong"), ownerPassword), false);
  assert.equal(basicOwnerAuthorizationMatches("Bearer " + ownerPassword, ownerPassword), false);
  assert.equal(basicOwnerAuthorizationMatches("Basic !!!", ownerPassword), false);
  assert.equal(basicOwnerAuthorizationMatches(null, ownerPassword), false);
});
