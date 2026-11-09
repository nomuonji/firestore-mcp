# Firestore MCP

A generic, multi-project Firestore MCP server hosted on Cloudflare Workers. It is independent of Tweet Operator, Keyword Operator, Vercel, and their application APIs.

## Features

- Streamable HTTP MCP endpoint: `/mcp`.
- One dedicated Google service account can access multiple Firestore projects through aliases.
- OAuth 2.1 authorization code flow with PKCE (S256), using stateless HMAC-signed codes and tokens.
- The existing `MCP_AUTH_TOKEN` is the shared HMAC signing key, the direct bearer key for trusted agents, and the owner password requested by a browser-native HTTP Basic authentication challenge. Any non-empty plaintext value is accepted; short non-empty plaintext values work, but are not recommended for an Internet-exposed production service.
- No KV, D1, Durable Object, database, or other OAuth session store is needed.
- Dashboard-managed Worker variables are preserved on deployment by `keep_vars: true`.

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

## Cloudflare Worker configuration

Set these three runtime variables on the Worker. They may be managed in Cloudflare Dashboard; the repository deliberately does not contain their values.

| Variable | Purpose |
| --- | --- |
| `MCP_AUTH_TOKEN` | Non-empty owner key; also signs stateless OAuth tokens. A short/simple value works but is substantially weaker. |
| `FIRESTORE_SERVICE_ACCOUNT_JSON` | Complete Google service-account JSON key. |
| `FIRESTORE_DATABASES` | JSON alias map for the target Firestore projects. |

Example `FIRESTORE_DATABASES`:

```json
{
  "keywords": { "projectId": "YOUR_KEYWORDS_PROJECT_ID", "databaseId": "(default)" },
  "tweets": { "projectId": "YOUR_TWEETS_PROJECT_ID", "databaseId": "(default)" }
}
```

**Important:** `wrangler.jsonc` sets `keep_vars: true`. This is intentional: Cloudflare normally removes Dashboard-managed plaintext variables when the next Wrangler deployment does not declare them. With `keep_vars: true`, dashboard-managed variables remain in place. This does not restore variables that were already removed by a previous deployment.

Do not commit actual credentials or put them in GitHub.

## OAuth protocol

OAuth is stateless and uses the same HMAC-SHA256 pattern as the existing Tweets Operator MCP.

- Issuer: `https://firestore-mcp.youfree731.workers.dev`
- Protected resource: `https://firestore-mcp.youfree731.workers.dev/mcp`
- Authorization endpoint: `/oauth/authorize`
- Token endpoint: `/oauth/token`
- Authorization server metadata: `/.well-known/oauth-authorization-server`
- Protected resource metadata: `/.well-known/oauth-protected-resource/mcp`
- Scopes: `firestore:access`, `offline_access`
- PKCE: S256 only
- Client authentication: `none`; no client secret required

Token lifetimes:

- Authorization code: 5 minutes
- Access token: 1 hour
- Refresh token: 30 days

The authorization code and tokens are signed self-contained values. They are validated cryptographically using `MCP_AUTH_TOKEN`; no server-side OAuth records are created.

Because this design intentionally has no storage, authorization codes are not tracked as consumed and cannot be individually revoked. PKCE and the 5-minute code lifetime limit exposure. Changing `MCP_AUTH_TOKEN` invalidates all outstanding OAuth tokens and direct bearer access immediately; users then authorize again.

## Connect from ChatGPT

In **Plugins → Add custom MCP server**:

- Name: `Firestore MCP`
- Connection: `https://firestore-mcp.youfree731.workers.dev/mcp`
- Authentication: `OAuth`
- Client registration: **User-Defined OAuth Client**
- OAuth Client ID: `firestore-mcp-chatgpt`
- OAuth Client Secret: leave blank
- Token endpoint auth method: `none`
- Scopes: `firestore:access offline_access`
- PKCE: enabled / S256
- OIDC: disabled

Auth URL, Token URL, issuer, and Resource should be discovered from the metadata after the Worker is redeployed. Do not select DCR or CIMD for this server; those registration modes are not implemented.

When ChatGPT opens the authorization URL, the browser receives an HTTP Basic authentication challenge. Enter username `owner` and the existing Cloudflare `MCP_AUTH_TOKEN` as the password. The credential is sent in the HTTPS `Authorization` header, not in a form body or URL query string; it is not used as ChatGPT's OAuth client secret. After authentication, the Worker redirects directly to the ChatGPT callback with a short-lived authorization code. ChatGPT then exchanges it for signed OAuth access and refresh tokens. No HTML form is rendered, so the flow does not depend on `form-action` CSP.

## Runtime checks

- `GET /health` returns only static service status.
- `GET /.well-known/oauth-authorization-server` returns OAuth discovery metadata.
- `GET /.well-known/oauth-protected-resource/mcp` returns protected resource metadata.
- An unauthenticated request to `/mcp` returns a 401 OAuth resource-metadata challenge.
- A valid signed OAuth access token or the original direct `MCP_AUTH_TOKEN` bearer key can call MCP tools.

## Local development

Copy `.dev.vars.example` to `.dev.vars`, replace the placeholders with local values, then:

```bash
npm install
npm run dev
```

Never commit `.dev.vars`.
