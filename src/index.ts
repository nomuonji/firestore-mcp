import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import { z } from "zod";
import { safeEqual } from "./core.js";
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

type ExecutionContextLike = {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
};

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

function authorized(request: Request, env: Env): boolean {
  if (!env.MCP_AUTH_TOKEN || env.MCP_AUTH_TOKEN.length < 32) return false;
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return Boolean(match && safeEqual(match[1]!, env.MCP_AUTH_TOKEN));
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContextLike): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health" && request.method === "GET") {
      return Response.json({ ok: true, service: "firestore-mcp" });
    }
    if (url.pathname !== "/mcp") {
      return new Response("Not Found", { status: 404 });
    }
    if (!authorized(request, env)) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: { "WWW-Authenticate": "Bearer" } });
    }
    const handler = createMcpHandler(() => createServer(env), { legacy: "stateless" });
    return handler.fetch(request);
  }
};
