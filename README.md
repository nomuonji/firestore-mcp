# Firestore MCP

A small, generic, multi-project Firestore MCP server hosted on Cloudflare Workers. It is deliberately independent of Tweet Operator, Keyword Operator, Vercel, and their application APIs.

## What it does

- Exposes one Streamable HTTP MCP endpoint: `/mcp`.
- Connects to multiple existing Firestore projects through configured aliases such as `tweets` and `keywords`.
- Uses one Google service account, granted access in each target project.
- Keeps the service-account key and MCP bearer token in Cloudflare Worker Secrets. The agent only receives the MCP bearer token and database aliases.
- Uses the Firestore REST API directly; no Firebase Admin SDK, Vercel runtime, or billed intermediary service is required.

### MCP tools

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

Normal JSON strings, numbers, booleans, nulls, arrays, and maps are supported. For Firestore-specific typed values, use `{"$timestamp":"2026-11-09T00:00:00Z"}` or `{"$reference":"projects/.../documents/..."}`. Returned timestamps and references use the same wrappers.

## Security model

- `MCP_AUTH_TOKEN`: a random bearer token used by MCP clients. Use at least 32 random bytes.
- `FIRESTORE_SERVICE_ACCOUNT_JSON`: one dedicated Google service-account JSON key.
- `FIRESTORE_DATABASES`: an allowlist mapping short aliases to Firestore project/database IDs.
- The Worker never exposes the service-account JSON, private key, OAuth access token, full project resource names, or raw upstream error bodies.
- The service account must be granted `roles/datastore.user` separately in each target Firebase/Google Cloud project. It does not need Owner or Editor.
- Use a dedicated service account rather than a personal user credential. Do not reuse a broad production administrator account.
- Firestore server credentials are authorized by IAM and bypass Firebase Security Rules. Treat this Worker as a privileged database gateway. Protect the MCP endpoint and only register trusted agents.
- The Worker is intentionally generic. It does not enforce application-specific field schemas or business rules.

## Deploy

### 1. Create or select a service account

Create one dedicated service account in an existing Google Cloud project. No new project or billing account is required for the Worker itself. Firestore API must already be enabled in each target project.

Grant this service account `roles/datastore.user` in each target project (for example, the existing Tweets and Keywords Firebase projects). The service account's home project does not have to be either target project.

### 2. Install dependencies and log in to Cloudflare

Requires Node.js 22+ and an existing Cloudflare account with Workers Free enabled.

```bash
npm install
npx wrangler login
```

### 3. Register Worker Secrets

Run these commands from the repository root. Each command reads the value interactively; do not put real secrets in source files or command-line history.

```bash
npx wrangler secret put MCP_AUTH_TOKEN
npx wrangler secret put FIRESTORE_SERVICE_ACCOUNT_JSON
npx wrangler secret put FIRESTORE_DATABASES
```

For `FIRESTORE_SERVICE_ACCOUNT_JSON`, paste the complete JSON key file.

For `FIRESTORE_DATABASES`, paste a JSON object using the real existing Firebase project IDs:

```json
{
  "tweets": { "projectId": "YOUR_TWEETS_PROJECT_ID", "databaseId": "(default)" },
  "keywords": { "projectId": "YOUR_KEYWORDS_PROJECT_ID", "databaseId": "(default)" }
}
```

Project IDs are configuration, not credentials. They are stored as a Worker Secret here to keep the routing table private and easy to set independently from source control. The MCP only returns the aliases.

Generate a strong MCP token locally, for example:

```bash
openssl rand -hex 32
```

Do not send the token or service-account JSON in chat, issues, or pull requests.

### 4. Deploy

```bash
npm run check
npx wrangler deploy
```

The endpoint is:

```text
https://firestore-mcp.<your-workers-subdomain>.workers.dev/mcp
```

Health check:

```text
https://firestore-mcp.<your-workers-subdomain>.workers.dev/health
```

`/health` returns only a static service status. All MCP requests require `Authorization: Bearer <MCP_AUTH_TOKEN>`.

### 5. Optional GitHub Actions deployment

The repository includes a manual deploy workflow. Add these GitHub Actions repository secrets:

- `CLOUDFLARE_API_TOKEN` with permission to deploy Workers.
- `CLOUDFLARE_ACCOUNT_ID`.

Then run **Actions → Deploy Cloudflare Worker → Run workflow**. The Google service-account key and MCP token remain in Cloudflare; they are never copied to GitHub Actions.

## Local development

Copy `.dev.vars.example` to `.dev.vars`, replace every placeholder with local test credentials, then:

```bash
npm install
npm run dev
```

Never commit `.dev.vars`.

## Notes and limits

- This is a direct database access layer, not a replacement for either Operator's API.
- Nested collection paths use alternating collection/document segments, e.g. `accounts/account-1/posts`.
- Queries are limited to one collection path, up to 10 AND-combined field filters, and 100 returned documents. Firestore may require indexes for some compound filters.
- List operations expose Firestore pagination tokens. Query pagination is not yet exposed.
- Updates patch supplied top-level fields; maps supplied as a value replace that top-level map field.
- Delete requires the document's current `updateTime` to prevent deleting a changed document after it was read.
- Worker secrets are separate from GitHub repository secrets.
