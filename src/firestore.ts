import {
  assertCollectionPath,
  assertDocumentData,
  assertDocumentPath,
  assertFieldPath,
  assertParentDocumentPath,
  decodeFields,
  encodeFields,
  encodeUpdateFieldPath,
  encodeValue,
  publicDocument
} from "./core.js";

export interface DatabaseTarget {
  projectId: string;
  databaseId: string;
}

export interface FirestoreEnv {
  FIRESTORE_DATABASES?: string;
  FIRESTORE_SERVICE_ACCOUNT_JSON?: string;
}

interface ServiceAccount {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

interface TokenResponse {
  access_token?: string;
  expires_in?: number;
  error?: string;
}

let tokenCache: { token: string; expiresAt: number } | undefined;
let tokenInFlight: Promise<string> | undefined;

function parseServiceAccount(env: FirestoreEnv): ServiceAccount {
  if (!env.FIRESTORE_SERVICE_ACCOUNT_JSON) {
    throw new Error("Firestore credentials are not configured.");
  }
  let account: Partial<ServiceAccount>;
  try {
    account = JSON.parse(env.FIRESTORE_SERVICE_ACCOUNT_JSON) as Partial<ServiceAccount>;
  } catch {
    throw new Error("Firestore credentials are not valid JSON.");
  }
  if (typeof account.client_email !== "string" || !account.client_email.includes("@") || typeof account.private_key !== "string" || !account.private_key.includes("PRIVATE KEY")) {
    throw new Error("Firestore credentials are missing required service-account fields.");
  }
  if (account.token_uri && account.token_uri !== "https://oauth2.googleapis.com/token") {\n    throw new Error("Service-account token_uri must be the standard Google OAuth endpoint.");\n  }\n  return account as ServiceAccount;
}

export function resolveDatabase(env: FirestoreEnv, alias: string): DatabaseTarget {
  if (!env.FIRESTORE_DATABASES) throw new Error("Firestore database aliases are not configured.");
  let databases: Record<string, unknown>;
  try {
    databases = JSON.parse(env.FIRESTORE_DATABASES) as Record<string, unknown>;
  } catch {
    throw new Error("Firestore database alias configuration is not valid JSON.");
  }
  const target = databases[alias] as Partial<DatabaseTarget> | undefined;
  if (!target || typeof target.projectId !== "string" || typeof target.databaseId !== "string") {
    throw new Error("Unknown database alias. Call list_databases to see configured aliases.");
  }
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(target.projectId) || !/^(\(default\)|[A-Za-z][A-Za-z0-9_-]{0,62})$/.test(target.databaseId)) {
    throw new Error("The selected database alias has an invalid target configuration.");
  }
  return { projectId: target.projectId, databaseId: target.databaseId };
}

export function listDatabaseAliases(env: FirestoreEnv): string[] {
  if (!env.FIRESTORE_DATABASES) return [];
  let databases: Record<string, unknown>;
  try {
    databases = JSON.parse(env.FIRESTORE_DATABASES) as Record<string, unknown>;
  } catch {
    throw new Error("Firestore database alias configuration is not valid JSON.");
  }
  return Object.keys(databases).filter((key) => /^[a-z][a-z0-9_-]{0,63}$/.test(key)).sort();
}

function baseDocumentsUrl(target: DatabaseTarget): string {
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(target.projectId)}/databases/${encodeURIComponent(target.databaseId)}/documents`;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function jsonBase64Url(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

async function issueAccessToken(env: FirestoreEnv): Promise<string> {
  const account = parseServiceAccount(env);
  const now = Math.floor(Date.now() / 1000);
  const header = jsonBase64Url({ alg: "RS256", typ: "JWT" });
  const payload = jsonBase64Url({
    iss: account.client_email,
    sub: account.client_email,
    aud: account.token_uri ?? "https://oauth2.googleapis.com/token",
    scope: "https://www.googleapis.com/auth/datastore",
    iat: now,
    exp: now + 3600
  });
  const unsigned = `${header}.${payload}`;
  const pem = account.private_key.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  let keyBytes: Uint8Array;
  try {
    keyBytes = Uint8Array.from(atob(pem), (character) => character.charCodeAt(0));
  } catch {
    throw new Error("Service-account private key could not be decoded.");
  }
  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyBytes,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned)));
  const assertion = `${unsigned}.${base64Url(signature)}`;
  const response = await fetch(account.token_uri ?? "https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });
  const body = await response.json() as TokenResponse;
  if (!response.ok || !body.access_token) {
    throw new Error(`Google OAuth token exchange failed (HTTP ${response.status}). Check the service-account key and IAM grants.`);
  }
  tokenCache = {
    token: body.access_token,
    expiresAt: Date.now() + Math.max(60, (body.expires_in ?? 3600) - 120) * 1000
  };
  return body.access_token;
}

async function accessToken(env: FirestoreEnv): Promise<string> {
  if (tokenCache && tokenCache.expiresAt > Date.now()) return tokenCache.token;
  if (!tokenInFlight) {
    tokenInFlight = issueAccessToken(env).finally(() => {
      tokenInFlight = undefined;
    });
  }
  return tokenInFlight;
}

async function firestoreRequest<T>(
  env: FirestoreEnv,
  target: DatabaseTarget,
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const token = await accessToken(env);
  const response = await fetch(`${baseDocumentsUrl(target)}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...init.headers
    }
  });
  if (!response.ok) {
    let code = "";
    try {
      const error = await response.json() as { error?: { status?: string } };
      code = error.error?.status ?? "";
    } catch {
      // Do not surface upstream bodies; they can contain resource identifiers.
    }
    const label = code ? ` (${code})` : "";
    throw new Error(`Firestore request failed: HTTP ${response.status}${label}.`);
  }
  if (response.status === 204) return null as T;
  return await response.json() as T;
}

function parentCollectionParts(collectionPath: string): { parent: string; collectionId: string } {
  const parts = assertCollectionPath(collectionPath);
  const collectionId = parts[parts.length - 1]!;
  const parentParts = parts.slice(0, -1);
  return {
    parent: parentParts.length ? `/${parentParts.map(encodeURIComponent).join("/")}` : "",
    collectionId
  };
}

export async function listCollections(
  env: FirestoreEnv,
  alias: string,
  parentDocumentPath?: string,
  pageSize = 100,
  pageToken?: string
) {
  const target = resolveDatabase(env, alias);
  const parentParts = assertParentDocumentPath(parentDocumentPath);
  const parent = `${baseDocumentsUrl(target)}${parentParts.length ? `/${parentParts.map(encodeURIComponent).join("/")}` : ""}`;
  const url = new URL(`${parent}:listCollectionIds`);
  url.searchParams.set("pageSize", String(pageSize));
  if (pageToken) url.searchParams.set("pageToken", pageToken);
  const token = await accessToken(env);
  const response = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ pageSize, ...(pageToken ? { pageToken } : {}) })
  });
  if (!response.ok) throw new Error(`Firestore collection listing failed: HTTP ${response.status}.`);
  const result = await response.json() as { collectionIds?: string[]; nextPageToken?: string };
  return { collections: result.collectionIds ?? [], ...(result.nextPageToken ? { nextPageToken: result.nextPageToken } : {}) };
}

export async function listDocuments(
  env: FirestoreEnv,
  alias: string,
  collectionPath: string,
  pageSize = 50,
  pageToken?: string
) {
  const target = resolveDatabase(env, alias);
  const { parent, collectionId } = parentCollectionParts(collectionPath);
  const url = new URL(`${baseDocumentsUrl(target)}${parent}/${encodeURIComponent(collectionId)}`);
  url.searchParams.set("pageSize", String(pageSize));
  if (pageToken) url.searchParams.set("pageToken", pageToken);
  const result = await firestoreRequest<{ documents?: Record<string, unknown>[]; nextPageToken?: string }>(
    env, target, `${parent}/${encodeURIComponent(collectionId)}?${url.searchParams.toString()}`
  );
  return {
    documents: (result.documents ?? []).map(publicDocument),
    ...(result.nextPageToken ? { nextPageToken: result.nextPageToken } : {})
  };
}

export async function getDocument(env: FirestoreEnv, alias: string, documentPath: string) {
  const target = resolveDatabase(env, alias);
  const parts = assertDocumentPath(documentPath);
  const path = `/${parts.map(encodeURIComponent).join("/")}`;
  const document = await firestoreRequest<Record<string, unknown>>(env, target, path);
  return publicDocument(document);
}

export async function queryDocuments(
  env: FirestoreEnv,
  alias: string,
  collectionPath: string,
  filters: Array<{ field: string; op: string; value: unknown }>,
  limit = 50,
  orderBy: Array<{ field: string; direction: "ASCENDING" | "DESCENDING" }> = []
) {
  const target = resolveDatabase(env, alias);
  const { parent, collectionId } = parentCollectionParts(collectionPath);
  const fieldFilters = filters.map((filter) => ({
    fieldFilter: {
      field: { fieldPath: assertFieldPath(filter.field) },
      op: filter.op,
      value: encodeValue(filter.value)
    }
  }));
  const where = fieldFilters.length === 1
    ? fieldFilters[0]
    : { compositeFilter: { op: "AND", filters: fieldFilters } };
  const query: Record<string, unknown> = {
    from: [{ collectionId }],
    where,
    limit,
    ...(orderBy.length ? {
      orderBy: orderBy.map((item) => ({
        field: { fieldPath: assertFieldPath(item.field) },
        direction: item.direction
      }))
    } : {})
  };
  const result = await firestoreRequest<Array<Record<string, unknown>>>(
    env,
    target,
    `${parent}:runQuery`,
    { method: "POST", body: JSON.stringify({ structuredQuery: query }) }
  );
  const documents = result
    .filter((row) => row.document)
    .map((row) => publicDocument(row.document as Record<string, unknown>));
  return { documents, returned: documents.length };
}

export async function createDocument(
  env: FirestoreEnv,
  alias: string,
  collectionPath: string,
  data: Record<string, unknown>,
  documentId?: string
) {
  const target = resolveDatabase(env, alias);
  const { parent, collectionId } = parentCollectionParts(collectionPath);
  if (documentId !== undefined && (!/^[^/]{1,1500}$/.test(documentId) || documentId === "." || documentId === "..")) {
    throw new Error("documentId is invalid.");
  }
  const query = documentId ? `?documentId=${encodeURIComponent(documentId)}` : "";
  const created = await firestoreRequest<Record<string, unknown>>(
    env,
    target,
    `${parent}/${encodeURIComponent(collectionId)}${query}`,
    { method: "POST", body: JSON.stringify({ fields: encodeFields(assertDocumentData(data)) }) }
  );
  return publicDocument(created);
}

export async function updateDocument(
  env: FirestoreEnv,
  alias: string,
  documentPath: string,
  data: Record<string, unknown>,
  expectedUpdateTime?: string
) {
  const target = resolveDatabase(env, alias);
  const parts = assertDocumentPath(documentPath);
  const fields = assertDocumentData(data);
  if (Object.keys(fields).length === 0) throw new Error("data must contain at least one field.");
  const params = new URLSearchParams();
  for (const key of Object.keys(fields)) params.append("updateMask.fieldPaths", encodeUpdateFieldPath(key));
  params.set("currentDocument.exists", "true");
  if (expectedUpdateTime) params.set("currentDocument.updateTime", expectedUpdateTime);
  const updated = await firestoreRequest<Record<string, unknown>>(
    env,
    target,
    `/${parts.map(encodeURIComponent).join("/")}?${params.toString()}`,
    { method: "PATCH", body: JSON.stringify({ fields: encodeFields(fields) }) }
  );
  return publicDocument(updated);
}

export async function deleteDocument(
  env: FirestoreEnv,
  alias: string,
  documentPath: string,
  expectedUpdateTime: string
) {
  const target = resolveDatabase(env, alias);
  const parts = assertDocumentPath(documentPath);
  const params = new URLSearchParams({ "currentDocument.updateTime": expectedUpdateTime });
  await firestoreRequest<null>(
    env,
    target,
    `/${parts.map(encodeURIComponent).join("/")}?${params.toString()}`,
    { method: "DELETE" }
  );
  return { deleted: true };
}
