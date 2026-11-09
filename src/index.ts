import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import { z } from "zod";
import { extractBearerToken, safeEqual } from "./core.js";
import { parseOAuthScopes, pkceChallenge, safeOAuthRedirect, sameAccessKey, signOAuthToken, verifyOAuthToken } from "./oauth.js";
import {
  createDocument,
  deleteDocument,
  FirestoreEnv,
  getDocument,
  listCollections,
  listDatabaseAliases,
  listDocuments,
  queryDocuments,
  updateDocument
} from "./firestore.js";

interface Env extends FirestoreEnv {
  MCP_AUTH_TOKEN?: string;
}

function result(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data) }],
    structuredContent: data as Record<string, unknown>
  };
}

function failure(error: unknown) {
  const message = error instanceof Error ? error.message : "Unknown operation error.";
  return {
    isError: true,
    content: [{ type: "text" as const, text: message }]
  };
}

async function run<T>(operation: () => Promise<T>) {
  try {
    return result(await operation());
  } catch (error) {
    return failure(error);
  }
}

function createServer(env: Env) {
  const server = new McpServer({
    name: "firestore-mcp",
    version: "1.0.0"
  });

  server.registerTool(
    "list_databases",
    {
      description: "List configured Firestore database aliases. Project IDs and credentials are never returned.",
      inputSchema: z.object({})
    },
    async () => run(async () => ({ databases: listDatabaseAliases(env) }))
  );

  server.registerTool(
    "list_collections",
    {
      description: "List collection IDs at the database root or beneath a document.",
      inputSchema: z.object({
        database: z.string().min(1).max(64),
        parentDocumentPath: z.string().max(6000).optional(),
        pageSize: z.number().int().min(1).max(1000).optional(),
        pageToken: z.string().max(4096).optional()
      })
    },
    async ({ database, parentDocumentPath, pageSize, pageToken }) =>
      run(() => listCollections(env, database, parentDocumentPath, pageSize ?? 100, pageToken))
  );

  server.registerTool(
    "list_documents",
    {
      description: "List documents in a collection or nested collection. Returns decoded document data and pagination token.",
      inputSchema: z.object({
        database: z.string().min(1).max(64),
        collectionPath: z.string().min(1).max(6000),
        pageSize: z.number().int().min(1).max(100).optional(),
        pageToken: z.string().max(4096).optional()
      })
    },
    async ({ database, collectionPath, pageSize, pageToken }) =>
      run(() => listDocuments(env, database, collectionPath, pageSize ?? 50, pageToken))
  );

  server.registerTool(
    "get_document",
    {
      description: "Get one document by its collection/document path.",
      inputSchema: z.object({
        database: z.string().min(1).max(64),
        documentPath: z.string().min(1).max(6000)
      })
    },
    async ({ database, documentPath }) =>
      run(() => getDocument(env, database, documentPath))
  );

  server.registerTool(
    "query_documents",
    {
      description: "Query documents in a collection with AND-combined field filters. Values use normal JSON types; timestamps and references can use {$timestamp: ISO_STRING} and {$reference: RESOURCE_NAME}.",
      inputSchema: z.object({
        database: z.string().min(1).max(64),
        collectionPath: z.string().min(1).max(6000),
        filters: z.array(z.object({
          field: z.string().min(1).max(1500),
          op: z.enum(["EQUAL", "NOT_EQUAL", "LESS_THAN", "LESS_THAN_OR_EQUAL", "GREATER_THAN", "GREATER_THAN_OR_EQUAL", "ARRAY_CONTAINS", "IN", "ARRAY_CONTAINS_ANY", "NOT_IN"]),
          value: z.unknown()
        })).min(1).max(10),
        limit: z.number().int().min(1).max(100).optional(),
        orderBy: z.array(z.object({
          field: z.string().min(1).max(1500),
          direction: z.enum(["ASCENDING", "DESCENDING"])
        })).max(3).optional()
      })
    },
    async ({ database, collectionPath, filters, limit, orderBy }) =>
      run(() => queryDocuments(env, database, collectionPath, filters, limit ?? 50, orderBy ?? []))
  );

  server.registerTool(
    "create_document",
    {
      description: "Create a Firestore document. Omit documentId to let Firestore generate one.",
      inputSchema: z.object({
        database: z.string().min(1).max(64),
        collectionPath: z.string().min(1).max(6000),
        documentId: z.string().min(1).max(1500).optional(),
        data: z.record(z.string(), z.unknown())
      })
    },
    async ({ database, collectionPath, documentId, data }) =>
      run(() => createDocument(env, database, collectionPath, data, documentId))
  );

  server.registerTool(
    "update_document",
    {
      description: "Update selected top-level fields of an existing document; unrelated fields are preserved. Optionally provide updateTime from a previous read for optimistic concurrency control.",
      inputSchema: z.object({
        database: z.string().min(1).max(64),
        documentPath: z.string().min(1).max(6000),
        data: z.record(z.string(), z.unknown()),
        expectedUpdateTime: z.string().min(1).max(64).optional()
      })
    },
    async ({ database, documentPath, data, expectedUpdateTime }) =>
      run(() => updateDocument(env, database, documentPath, data, expectedUpdateTime))
  );

  server.registerTool(
    "delete_document",
    {
      description: "Permanently delete one document. Requires confirm=true and the exact updateTime returned by get_document or list_documents.",
      inputSchema: z.object({
        database: z.string().min(1).max(64),
        documentPath: z.string().min(1).max(6000),
        confirm: z.literal(true),
        expectedUpdateTime: z.string().min(1).max(64)
      })
    },
    async ({ database, documentPath, expectedUpdateTime }) =>
      run(() => deleteDocument(env, database, documentPath, expectedUpdateTime))
  );

  return server;
}


const FIRESTORE_SCOPE = "firestore:access";

function originOf(request: Request): string {
  return new URL(request.url).origin;
}

function resourceOf(request: Request): string {
  return originOf(request) + "/mcp";
}

function jsonResponse(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: { "Cache-Control": "no-store", Pragma: "no-cache" }
  });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    };
    return entities[character]!;
  });
}

function authorizationPage(values: {
  action: string;
  clientId: string;
  redirectUri: string;
  state: string;
  scope: string;
  challenge: string;
  error?: string;
}): Response {
  const hidden = [
    ["client_id", values.clientId],
    ["redirect_uri", values.redirectUri],
    ["state", values.state],
    ["scope", values.scope],
    ["code_challenge", values.challenge],
    ["code_challenge_method", "S256"]
  ].map(([key, value]) =>
    '<input type="hidden" name="' + key + '" value="' + escapeHtml(value) + '">'
  ).join("");
  const error = values.error
    ? '<p class="error">' + escapeHtml(values.error) + "</p>"
    : "";
  const html = [
    "<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">",
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    "<title>Firestore MCP 接続許可</title>",
    "<style>",
    "body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:1.25rem;background:#f5f7fa;color:#18212b}",
    ".card{background:#fff;border:1px solid #dce2e8;border-radius:14px;padding:24px}",
    "h1{font-size:1.4rem}p,small{line-height:1.6;color:#4e5b68}",
    "input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0;font:inherit;border-radius:8px}",
    "input{border:1px solid #b8c2cc}button{background:#1769aa;color:white;border:0;font-weight:700;cursor:pointer}",
    ".deny{background:#e8edf2;color:#23303d}.error{color:#9b2424;background:#fff0f0;padding:10px;border-radius:8px}",
    "</style></head><body><main class=\"card\">",
    "<h1>Firestore MCPへのアクセスを許可しますか？</h1>",
    "<p><strong>" + escapeHtml(values.clientId) + "</strong> が、設定済みのFirestoreデータベース（keywords / tweets）にアクセスします。</p>",
    "<p>許可される操作はFirestoreの読み取り・作成・更新・削除です。</p>",
    error,
    '<form method="post" action="' + escapeHtml(values.action) + '">',
    hidden,
    '<label>管理用アクセスキー（Cloudflareの MCP_AUTH_TOKEN）',
    '<input name="access_key" type="password" autocomplete="current-password" required></label>',
    "<small>既存の MCP_AUTH_TOKEN を入力してください。ChatGPTへこの値は渡されません。</small>",
    '<button type="submit" name="decision" value="approve">許可して接続</button>',
    '<button class="deny" type="submit" name="decision" value="deny" formnovalidate>拒否</button>',
    "</form></main></body></html>"
  ].join("");
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://firestore-mcp.youfree731.workers.dev; base-uri 'none'; frame-ancestors 'none'"
    }
  });
}

async function authorizeGet(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const redirectUri = safeOAuthRedirect(url.searchParams.get("redirect_uri") ?? "");
  const clientId = url.searchParams.get("client_id") ?? "";
  const responseType = url.searchParams.get("response_type") ?? "";
  const challenge = url.searchParams.get("code_challenge") ?? "";
  const method = url.searchParams.get("code_challenge_method") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const resource = url.searchParams.get("resource") ?? resourceOf(request);

  let scope: string[];
  try {
    scope = parseOAuthScopes(url.searchParams.get("scope") ?? "");
  } catch {
    return new Response("Unsupported OAuth scope.", { status: 400 });
  }

  if (!env.MCP_AUTH_TOKEN) {
    return new Response("MCP_AUTH_TOKEN is not configured.", { status: 503 });
  }
  if (
    responseType !== "code" ||
    !redirectUri ||
    !clientId ||
    clientId.length > 512 ||
    !/^[A-Za-z0-9._~:-]+$/.test(clientId) ||
    !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) ||
    method !== "S256" ||
    state.length > 2048 ||
    resource !== resourceOf(request)
  ) {
    return new Response("Invalid OAuth authorization request.", { status: 400 });
  }

  return authorizationPage({
    action: url.origin + "/oauth/authorize",
    clientId,
    redirectUri: redirectUri.toString(),
    state,
    scope: scope.join(" "),
    challenge
  });
}

async function authorizePost(request: Request, env: Env): Promise<Response> {
  if (!env.MCP_AUTH_TOKEN) {
    return new Response("MCP_AUTH_TOKEN is not configured.", { status: 503 });
  }
  const form = await request.formData();
  const redirectUri = safeOAuthRedirect(String(form.get("redirect_uri") ?? ""));
  const clientId = String(form.get("client_id") ?? "");
  const state = String(form.get("state") ?? "");
  const challenge = String(form.get("code_challenge") ?? "");
  const method = String(form.get("code_challenge_method") ?? "");
  const decision = String(form.get("decision") ?? "approve");
  let scope: string[];

  try {
    scope = parseOAuthScopes(String(form.get("scope") ?? ""));
  } catch {
    return new Response("Unsupported OAuth scope.", { status: 400 });
  }

  if (decision === "deny") {
    if (!redirectUri) return new Response("Invalid redirect URI.", { status: 400 });
    redirectUri.searchParams.set("error", "access_denied");
    if (state) redirectUri.searchParams.set("state", state);
    return Response.redirect(redirectUri.toString(), 302);
  }

  const accessKey = String(form.get("access_key") ?? "");
  if (
    !redirectUri ||
    !clientId ||
    !/^[A-Za-z0-9._~:-]+$/.test(clientId) ||
    !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) ||
    method !== "S256" ||
    state.length > 2048 ||
    !sameAccessKey(accessKey, env.MCP_AUTH_TOKEN)
  ) {
    return new Response("Authorization denied. Check the access key and authorization request.", { status: 401 });
  }

  const resource = resourceOf(request);
  const code = await signOAuthToken("code", {
    redirectUri: redirectUri.toString(),
    clientId,
    challenge,
    scope: scope.join(" "),
    aud: resource
  }, env.MCP_AUTH_TOKEN);

  redirectUri.searchParams.set("code", code);
  if (state) redirectUri.searchParams.set("state", state);
  return Response.redirect(redirectUri.toString(), 302);
}

async function tokenPost(request: Request, env: Env): Promise<Response> {
  if (!env.MCP_AUTH_TOKEN) {
    return jsonResponse({ error: "server_error", error_description: "MCP_AUTH_TOKEN is not configured." }, 503);
  }
  const form = await request.formData();
  const grantType = String(form.get("grant_type") ?? "");
  const resource = String(form.get("resource") ?? resourceOf(request));
  const clientId = String(form.get("client_id") ?? "");

  if (resource !== resourceOf(request)) {
    return jsonResponse({ error: "invalid_target" }, 400);
  }

  if (grantType === "refresh_token") {
    const refresh = await verifyOAuthToken(
      String(form.get("refresh_token") ?? ""),
      "refresh",
      env.MCP_AUTH_TOKEN
    );
    if (
      !refresh ||
      refresh.aud !== resource ||
      typeof refresh.clientId !== "string" ||
      (clientId && refresh.clientId !== clientId)
    ) {
      return jsonResponse({ error: "invalid_grant" }, 400);
    }

    const scope = String(refresh.scope ?? FIRESTORE_SCOPE);
    const accessToken = await signOAuthToken("access", {
      clientId: refresh.clientId,
      scope,
      aud: resource
    }, env.MCP_AUTH_TOKEN);
    const newRefreshToken = await signOAuthToken("refresh", {
      clientId: refresh.clientId,
      scope,
      aud: resource
    }, env.MCP_AUTH_TOKEN);
    return jsonResponse({
      access_token: accessToken,
      refresh_token: newRefreshToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope
    });
  }

  if (grantType !== "authorization_code") {
    return jsonResponse({ error: "unsupported_grant_type" }, 400);
  }

  const code = await verifyOAuthToken(
    String(form.get("code") ?? ""),
    "code",
    env.MCP_AUTH_TOKEN
  );
  const verifier = String(form.get("code_verifier") ?? "");
  const redirectUri = String(form.get("redirect_uri") ?? "");
  const codeClientId = clientId || String(code?.clientId ?? "");

  if (
    !code ||
    !verifier ||
    typeof code.redirectUri !== "string" ||
    code.redirectUri !== redirectUri ||
    typeof code.clientId !== "string" ||
    code.clientId !== codeClientId ||
    code.aud !== resource ||
    await pkceChallenge(verifier) !== code.challenge
  ) {
    return jsonResponse({ error: "invalid_grant" }, 400);
  }

  const scope = String(code.scope ?? FIRESTORE_SCOPE);
  const accessToken = await signOAuthToken("access", {
    clientId: code.clientId,
    scope,
    aud: resource
  }, env.MCP_AUTH_TOKEN);
  const refreshToken = await signOAuthToken("refresh", {
    clientId: code.clientId,
    scope,
    aud: resource
  }, env.MCP_AUTH_TOKEN);

  return jsonResponse({
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope
  });
}

function authorizationServerMetadata(request: Request): Response {
  const origin = originOf(request);
  return jsonResponse({
    issuer: origin,
    authorization_endpoint: origin + "/oauth/authorize",
    token_endpoint: origin + "/oauth/token",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [FIRESTORE_SCOPE, "offline_access"]
  });
}

function protectedResourceMetadata(request: Request): Response {
  const origin = originOf(request);
  return jsonResponse({
    resource: origin + "/mcp",
    authorization_servers: [origin],
    scopes_supported: [FIRESTORE_SCOPE],
    bearer_methods_supported: ["header"]
  });
}

async function authorized(request: Request, env: Env): Promise<boolean> {
  if (!env.MCP_AUTH_TOKEN) return false;
  const token = extractBearerToken(request.headers.get("authorization"));
  if (!token) return false;

  // Keep the original direct agent bearer-token mode available.
  if (safeEqual(token, env.MCP_AUTH_TOKEN)) return true;

  const access = await verifyOAuthToken(token, "access", env.MCP_AUTH_TOKEN);
  return Boolean(
    access &&
    access.aud === resourceOf(request) &&
    typeof access.scope === "string" &&
    access.scope.split(/\s+/).includes(FIRESTORE_SCOPE)
  );
}

async function handleMcp(request: Request, env: Env): Promise<Response> {
  if (!(await authorized(request, env))) {
    const metadataUrl = originOf(request) + "/.well-known/oauth-protected-resource/mcp";
    const response = jsonResponse({ error: "Unauthorized" }, 401);
    response.headers.set("WWW-Authenticate", 'Bearer resource_metadata="' + metadataUrl + '"');
    return response;
  }
  const handler = createMcpHandler(() => createServer(env), { legacy: "stateless" });
  return handler.fetch(request);
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health" && request.method === "GET") {
      return jsonResponse({ ok: true, service: "firestore-mcp", auth: "oauth-stateless", storage: "none" });
    }
    if (
      (url.pathname === "/.well-known/oauth-protected-resource" ||
       url.pathname === "/.well-known/oauth-protected-resource/mcp") &&
      request.method === "GET"
    ) return protectedResourceMetadata(request);
    if (url.pathname === "/.well-known/oauth-authorization-server" && request.method === "GET") {
      return authorizationServerMetadata(request);
    }
    if (url.pathname === "/oauth/authorize" && request.method === "GET") return authorizeGet(request, env);
    if (url.pathname === "/oauth/authorize" && request.method === "POST") return authorizePost(request, env);
    if (url.pathname === "/oauth/token" && request.method === "POST") return tokenPost(request, env);
    if (url.pathname === "/mcp") return handleMcp(request, env);
    return new Response("Not Found", { status: 404 });
  }
};
