import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import { z } from "zod";
import { safeEqual } from "./core.js";
import OAuthProvider, { AuthorizationError, type ConsentDescription, type OAuthHelpers, type OAuthResourceAuth } from "@cloudflare/workers-oauth-provider";
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
  OAUTH_KV?: KVNamespace;
  OAUTH_PROVIDER?: OAuthHelpers;
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
const OAUTH_ISSUER = "https://firestore-mcp.youfree731.workers.dev";
const MCP_RESOURCE = `${OAUTH_ISSUER}/mcp`;

function legacyAuthorized(request: Request, env: Env): boolean {
  if (!env.MCP_AUTH_TOKEN || env.MCP_AUTH_TOKEN.length < 32) return false;
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer\\s+(.+)$/i.exec(header);
  return Boolean(match && safeEqual(match[1]!, env.MCP_AUTH_TOKEN));
}

function mcpHandler(request: Request, env: Env): Promise<Response> {
  const handler = createMcpHandler(() => createServer(env), { legacy: "stateless" });
  return handler.fetch(request);
}

function legacyFetch(request: Request, env: Env): Promise<Response> | Response {
  const url = new URL(request.url);
  if (url.pathname === "/health" && request.method === "GET") {
    return Response.json({ ok: true, service: "firestore-mcp", auth: "legacy-bearer", oauth: "not-configured" });
  }
  if (url.pathname !== "/mcp") return new Response("Not Found", { status: 404 });
  if (!legacyAuthorized(request, env)) {
    return Response.json(
      { error: "Unauthorized" },
      { status: 401, headers: { "WWW-Authenticate": 'Bearer realm="firestore-mcp"' } }
    );
  }
  return mcpHandler(request, env);
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

function scopeLabel(scope: string): string {
  if (scope === FIRESTORE_SCOPE) return "Firestoreの読み取り・書き込み（tweets / keywords）";
  if (scope === "offline_access") return "再接続を減らすための更新トークン";
  return scope;
}

function authorizationPage(
  details: ConsentDescription,
  handle: string,
  actionUrl: string,
  errorMessage?: string
): string {
  const clientName = escapeHtml(details.clientName);
  const redirectHost = escapeHtml(details.redirectHost);
  const clientDomain = details.clientDomain
    ? `<p class="domain">クライアントのドメイン: <strong>${escapeHtml(details.clientDomain)}</strong></p>`
    : '<p class="domain">このクライアント名はOAuthメタデータで申告されたものです。</p>';
  const scopes = details.scope
    .map((scope) => `<label class="scope"><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked> <span>${escapeHtml(scopeLabel(scope))}</span></label>`)
    .join("");
  const loopbackWarning = details.redirectIsLoopback
    ? '<p class="warning">この接続はローカル端末へ認証情報を返します。開始したアプリを確認してください。</p>'
    : "";
  const error = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : "";
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firestore MCPへのアクセス許可</title>
<style>
:root{color-scheme:light dark;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f8;color:#18212b}
main{box-sizing:border-box;width:min(92vw,520px);padding:28px;border-radius:16px;background:#fff;box-shadow:0 8px 32px #18212b18}
h1{font-size:1.45rem;margin:0 0 12px}
p{line-height:1.55;color:#44515f}
.domain{font-size:.92rem}
.scope{display:flex;gap:10px;align-items:flex-start;margin:14px 0;padding:12px;border:1px solid #d9e0e7;border-radius:9px}
input[type=password]{box-sizing:border-box;width:100%;padding:12px;border:1px solid #aeb9c5;border-radius:8px;margin:8px 0 16px;font:inherit}
button{padding:11px 16px;border:0;border-radius:8px;font:inherit;cursor:pointer}
.allow{background:#1769aa;color:white}
.deny{background:#e9edf1;color:#293644;margin-left:8px}
.error,.warning{padding:10px;border-radius:8px;background:#fff0f0;color:#9c2222}
small{color:#596675}
@media(prefers-color-scheme:dark){body{background:#101820;color:#e9eef3}main{background:#1b2834}p,small{color:#b7c3ce}.scope{border-color:#435361}input[type=password]{background:#101820;color:#fff;border-color:#52616f}.deny{background:#394957;color:#fff}}
</style>
</head>
<body>
<main>
<h1>Firestore MCPへのアクセスを許可しますか？</h1>
<p><strong>${clientName}</strong> がFirestoreデータベースにアクセスしようとしています。</p>
${clientDomain}
<p>認証結果の返却先: <strong>${redirectHost}</strong></p>
${loopbackWarning}
<p>許可する操作:</p>
${scopes}
${error}
<form method="post" action="${escapeHtml(actionUrl)}">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
<label for="password"><strong>管理パスワード</strong></label>
<input id="password" type="password" name="password" autocomplete="current-password" placeholder="Cloudflareに登録済みのMCP_AUTH_TOKEN" required>
<p><small>これはFirestore MCPの管理者確認用です。ChatGPTには保存・送信されません。</small></p>
<button class="allow" type="submit" name="decision" value="approve">アクセスを許可</button>
<button class="deny" type="submit" name="decision" value="deny" formnovalidate>拒否</button>
</form>
</main>
</body>
</html>`;
}

function pageResponse(
  html: string,
  headers: HeadersInit = {},
  status = 200
): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Content-Type", "text/html; charset=utf-8");
  responseHeaders.set("Cache-Control", "no-store");
  responseHeaders.set("Pragma", "no-cache");
  responseHeaders.set("X-Content-Type-Options", "nosniff");
  responseHeaders.set("X-Frame-Options", "DENY");
  responseHeaders.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  return new Response(html, { status, headers: responseHeaders });
}

async function authorize(request: Request, env: Env): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  if (!oauth) return new Response("OAuth is not configured.", { status: 503 });

  try {
    const authRequest = await oauth.parseAuthRequest(request);

    if (request.method === "GET") {
      const details = await oauth.describeConsent(authRequest);
      const consent = await oauth.beginConsent(authRequest);
      return pageResponse(authorizationPage(details, consent.handle, request.url), consent.headers);
    }

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, POST" } });
    }

    const form = await request.formData();
    const handle = String(form.get("handle") ?? "");
    const decision = String(form.get("decision") ?? "approve");

    if (decision === "deny") {
      const denied = await oauth.denyConsent(request, handle);
      const headers = new Headers(denied.headers);
      headers.set("Location", denied.redirectTo);
      return new Response(null, { status: 302, headers });
    }

    const password = String(form.get("password") ?? "");
    if (!env.MCP_AUTH_TOKEN || env.MCP_AUTH_TOKEN.length < 32 || !safeEqual(password, env.MCP_AUTH_TOKEN)) {
      const details = await oauth.describeConsent(authRequest);
      return pageResponse(
        authorizationPage(details, handle, request.url, "管理パスワードが正しくありません。"),
        {},
        401
      );
    }

    const selectedScopes = form.getAll("scope").map(String);
    const approved = await oauth.approveConsent(request, handle, { scope: selectedScopes });
    const client = await oauth.lookupClient(approved.request.clientId);
    const completed = await oauth.completeAuthorization({
      request: approved.request,
      userId: "firestore-owner",
      metadata: { clientName: client?.clientName ?? "ChatGPT" },
      scope: approved.request.scope,
      props: { userId: "firestore-owner" }
    });

    const headers = new Headers(approved.headers);
    headers.set("Location", completed.redirectTo);
    return new Response(null, { status: 302, headers });
  } catch (error) {
    if (error instanceof AuthorizationError) {
      if (error.redirectTo) return Response.redirect(error.redirectTo, 302);
      return new Response(error.description, { status: 400 });
    }
    throw error;
  }
}

const oauthProvider = new OAuthProvider<Env>({
  apiRoute: "/mcp",
  apiHandler: {
    async fetch(request, env, ctx) {
      const auth = (ctx as ExecutionContext & { auth?: OAuthResourceAuth }).auth;
      if (!auth?.scope.includes(FIRESTORE_SCOPE)) {
        return new Response("Insufficient scope.", { status: 403 });
      }
      return mcpHandler(request, env);
    }
  },
  defaultHandler: {
    async fetch(request, env) {
      const url = new URL(request.url);
      if (url.pathname === "/authorize") return authorize(request, env);
      if (url.pathname === "/health" && request.method === "GET") {
        return Response.json({ ok: true, service: "firestore-mcp", auth: "oauth" });
      }
      return new Response("Not Found", { status: 404 });
    }
  },
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  scopesSupported: [FIRESTORE_SCOPE, "offline_access"],
  resourceMetadata: {
    resource: MCP_RESOURCE,
    authorization_servers: [OAUTH_ISSUER],
    resource_name: "Firestore MCP"
  },
  requiredScopes: [FIRESTORE_SCOPE],
  clientIdMetadataDocumentEnabled: true,
  refreshTokenTTL: 30 * 24 * 60 * 60
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Keep the existing bearer-token deployment working until its KV namespace is bound.
    if (!env.OAUTH_KV) return legacyFetch(request, env);
    return oauthProvider.fetch(request, env, ctx);
  }
};
