import { safeEqual } from "./core.js";

export type OAuthTokenKind = "code" | "access" | "refresh";
export type OAuthClaims = Record<string, unknown> & {
  kind: OAuthTokenKind;
  iat: number;
  exp: number;
};

const encoder = new TextEncoder();

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

const TTL_SECONDS: Record<OAuthTokenKind, number> = {
  code: 5 * 60,
  access: 60 * 60,
  refresh: 30 * 24 * 60 * 60
};

/**
 * Stateless OAuth tokens signed with the shared MCP_AUTH_TOKEN owner key.
 * No KV, D1, Durable Object, or other state store is needed. Authorization codes
 * are short-lived and PKCE-bound.
 */
export async function signOAuthToken(
  kind: OAuthTokenKind,
  claims: Record<string, unknown>,
  secret: string,
  nowMs = Date.now()
): Promise<string> {
  if (secret.length < 32) throw new Error("MCP_AUTH_TOKEN must contain at least 32 characters.");
  const now = Math.floor(nowMs / 1000);
  const body = base64Url(encoder.encode(JSON.stringify({
    ...claims,
    kind,
    iat: now,
    exp: now + TTL_SECONDS[kind]
  })));
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", await hmacKey(secret), encoder.encode(body))
  );
  return body + "." + base64Url(signature);
}

export async function verifyOAuthToken(
  value: string,
  kind: OAuthTokenKind,
  secret: string,
  nowMs = Date.now()
): Promise<OAuthClaims | null> {
  if (secret.length < 32) return null;
  const parts = value.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;

  try {
    const valid = await crypto.subtle.verify(
      "HMAC",
      await hmacKey(secret),
      fromBase64Url(parts[1]),
      encoder.encode(parts[0])
    );
    if (!valid) return null;

    const claims = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0]))) as Record<string, unknown>;
    const now = Math.floor(nowMs / 1000);
    if (
      claims.kind !== kind ||
      typeof claims.iat !== "number" ||
      claims.iat > now + 60 ||
      typeof claims.exp !== "number" ||
      claims.exp <= now
    ) return null;

    return claims as OAuthClaims;
  } catch {
    return null;
  }
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  return base64Url(new Uint8Array(digest));
}

export function sameAccessKey(value: string, expected: string | undefined): boolean {
  return Boolean(expected && expected.length >= 32 && safeEqual(value, expected));
}

/** Restrict OAuth redirects to ChatGPT's callback domain (plus loopback for local testing). */
export function safeOAuthRedirect(value: string): URL | null {
  try {
    const url = new URL(value);
    if (url.protocol === "https:" && (url.hostname === "chatgpt.com" || url.hostname.endsWith(".chatgpt.com"))) {
      return url;
    }
    if (
      url.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
    ) return url;
    return null;
  } catch {
    return null;
  }
}

export function parseOAuthScopes(value: string): string[] {
  const requested = value.trim() ? value.trim().split(/\s+/) : ["firestore:access", "offline_access"];
  const allowed = new Set(["firestore:access", "offline_access"]);
  if (!requested.includes("firestore:access") || requested.some((scope) => !allowed.has(scope))) {
    throw new Error("Unsupported OAuth scope.");
  }
  return [...new Set(requested)];
}
