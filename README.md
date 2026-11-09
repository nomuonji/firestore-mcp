# Firestore MCP

A generic, multi-project Firestore MCP server hosted on Cloudflare Workers. It is independent of Tweet Operator, Keyword Operator, Vercel, and their application APIs.

## Features

- Streamable HTTP MCP endpoint: `/mcp`.
- One service account can access multiple Firestore projects via aliases.
- OAuth 2.1 authorization code flow with PKCE (S256), CIMD client identification, resource-bound access tokens, refresh-token rotation, and consent.
- Cloudflare's maintained `@cloudflare/workers-oauth-provider` handles OAuth discovery, token issuance/validation, and token storage.
- The service-account key remains inside the Worker and is never sent to ChatGPT.

## MCP tools

| Tool | Purpose |
| --- | --- |
| `list_databases` | List configured aliases only; never returns project IDs. |
| `list_collections` | List root or nested collection IDs. |
| `list_documents` | List collection documents with pagination. |
| `get_document` | Read one document. |
| `query_documents` | Query using up to 10 AND-combined field filters. |
| `create_document` | Create a document with an optional explicit ID. |
| `update_document` | Patch top-level fields while preserving unrelated fields. |
| `delete_document` | Delete only with `confirm: true` and the exact document `updateTime`. |

## Google Cloud setup

Create one dedicated service account in an existing project. Grant it `roles/datastore.user` in every target Firestore project. The service-account key is used only by the Worker.

## Cloudflare Worker setup

### 1. Create an OAuth KV namespace

OAuth authorization codes, grants, and tokens need server-side storage. Create one free Workers KV namespace:

```bash
npx wrangler login
npx wrangler kv namespace create FIRESTORE_MCP_OAUTH
```

The command returns a namespace ID. Add it to `wrangler.jsonc` as the `OAUTH_KV` binding:

```jsonc
"kv_namespaces": [
  { "binding": "OAUTH_KV", "id": "PASTE_THE_RETURNED_NAMESPACE_ID" }
]
```

The namespace ID is configuration, not a credential. Keep it in the repository config. The OAuth provider stores authorization data in this namespace; do not use a namespace shared with another application.

The Worker continues to serve the old Bearer-token mode until this binding is present. After adding the binding and deploying, OAuth becomes active.

### 2. Configure Worker variables

Keep these names exactly as shown:

- `MCP_AUTH_TOKEN`: long random owner password (at least 32 characters). The browser asks for it on the OAuth consent page. It is not the MCP access token and is not entered into ChatGPT's OAuth client fields.
- `FIRESTORE_SERVICE_ACCOUNT_JSON`: complete Google service-account JSON key.
- `FIRESTORE_DATABASES`: target aliases.

Example `FIRESTORE_DATABASES`:

```json
{
  "keywords": { "projectId": "precise-armor-390514", "databaseId": "(default)" },
  "tweets": { "projectId": "selection-to-spreadsheet", "databaseId": "(default)" }
}
```

Use Cloudflare Worker variables or secrets. The service-account JSON and owner password should preferably be Secrets; the Worker code reads either binding identically. Never put their values in GitHub.

### 3. Deploy and verify

```bash
npm install
npm run check
npx wrangler deploy
```

Check:

- `GET /health` returns a static service status.
- `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-authorization-server` return OAuth discovery metadata.
- An unauthenticated MCP call to `/mcp` returns 401 with a `resource_metadata` challenge.
- After ChatGPT authorization, MCP calls include a valid resource-bound OAuth bearer token.

### 4. Connect ChatGPT

Create a custom MCP connector using:

- Connection URL: `https://firestore-mcp.youfree731.workers.dev/mcp`
- Authentication: `OAuth`
- Client registration: choose **Client Identifier Metadata Document (CIMD)** when offered. Do not choose User-Defined OAuth Client; there is no client secret to enter.
- Allow the connector to discover the authorization and token URLs from the server metadata.

When ChatGPT opens the authorization page, enter the `MCP_AUTH_TOKEN` owner password stored in Worker settings, then explicitly approve Firestore access.

## OAuth behavior

- OAuth issuer: `https://firestore-mcp.youfree731.workers.dev`
- Resource: `https://firestore-mcp.youfree731.workers.dev/mcp`
- Authorization endpoint: `/authorize`
- Token endpoint: `/oauth/token`
- Supported scopes: `firestore:access`, `offline_access`
- CIMD is enabled; DCR is intentionally not exposed.
- Only the configured ChatGPT resource receives tokens. The authorization page displays the client/domain and redirect hostname before approval.

## Security notes

- Firestore server credentials bypass Firebase Security Rules. IAM is enforced through `roles/datastore.user`.
- `MCP_AUTH_TOKEN` is the owner sign-in password after OAuth is enabled; rotate it if exposed.
- OAuth tokens, grants, and authorization codes are managed by Cloudflare's OAuth provider and stored in Workers KV.
- `delete_document` still requires explicit `confirm: true` and the exact `updateTime`.
- The Worker does not return Google credentials, project resource names, or raw upstream error bodies.

## Local development

Copy `.dev.vars.example` to `.dev.vars`, create a development KV namespace and bind it in `wrangler.jsonc`, then:

```bash
npm install
npm run dev
```

Never commit `.dev.vars`.
