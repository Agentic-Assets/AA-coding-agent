# External MCP clients: configuration guide and API Keys UI

This guide covers **how end users connect external MCP applications** (Claude Desktop, Cursor, Windsurf, scripts, and other HTTP MCP clients) **to this platform’s MCP endpoint** (`/api/mcp`). It also describes **how that experience is presented in the web UI**—layout, behavior, and copy-to-clipboard flows—so you can replicate similar UX in another product.

For the **other** MCP concept in this repo—adding MCP servers **inside** tasks so sandbox agents can call third-party tools—see [MCP_CONNECTORS_UI_AND_ARCHITECTURE.md](./MCP_CONNECTORS_UI_AND_ARCHITECTURE.md).

---

## What “external MCP” means here

| Direction | Meaning |
| --- | --- |
| **Inbound (this doc)** | An **external** app runs an MCP client; it connects **to your deployment** at `{origin}/api/mcp` using an **API token**. The client can invoke tools such as `create-task`, `get-task`, etc. |
| **Outbound (connectors)** | Your platform runs an agent in a sandbox; the agent uses **connectors** you configured in **MCP Servers** to reach **other** services’ MCP endpoints. |

Authentication for inbound MCP is documented in [MCP_SERVER.md](./MCP_SERVER.md) (Bearer token, optional `?apikey=` query parameter, session fallback).

---

## Prerequisites before configuring clients

1. **Sign in** to the web app and **connect GitHub** (required for repo-backed tasks over MCP).
2. **Create at least one API token** in the UI (see below). The raw token is shown **once** at creation; after that, clients must use a token you saved elsewhere.

---

## Where to open the configuration UI in this app

The **API Keys** dialog is opened from the **signed-in user menu** (see `components/auth/sign-out.tsx`: menu item triggers `ApiKeysDialog`).

**Implementation:** `components/api-keys-dialog.tsx` — single scrollable dialog (`DialogContent` with `max-w-2xl`, `max-h-[85vh]`, `overflow-y-auto`, responsive padding).

---

## How the API Keys dialog is structured (visual and functional)

The dialog is one vertical column with **horizontal dividers** between major sections. It uses **shadcn/ui** primitives (`Dialog`, `Button`, `Input`, `Label`) and Tailwind: compact rows (`h-8` inputs), **muted** subtitle text (`text-muted-foreground`), and **soft code panels** (`rounded-md bg-muted/50`) for examples.

### Section 1 — Provider API keys

- **Title:** “API Keys”
- **Subtitle:** “Configure your own API keys. System defaults will be used if not provided.”
- **Rows:** One row per provider (AI Gateway, Anthropic, OpenAI, Gemini, Cursor, GitHub). Each row has a **fixed-width label**, **password-style input** (toggle eye icon to reveal), and **Save** or **Clear**.
- **Behavior:** Saved keys show masked bullets until “Show” is used; **Clear** lets the user replace a key.

### Section 2 — External API access (tokens)

- **Heading:** “External API Access”
- **Subtext:** “Call the coding agent from external apps”
- **Create token:** Name field + **Create** button. On success, an **amber-bordered** panel appears: warning icon, “Copy this token now…”, read-only mono input, **Copy**, **Done**. The raw token auto-hides after ~60 seconds client-side.
- **Token list:** Named tokens with **prefix** (not full secret), last-used date, trash to delete.
- **Usage example:** Labeled “Usage Example”; **curl** `POST` to `/api/tasks` with `Authorization: Bearer …`. Uses **`YOUR_API_KEY`** as placeholder until a token was **just** created (then the template substitutes that token for curl/MCP strings).

### Section 3 — MCP Server (external clients)

- **Heading:** “MCP Server”
- **Subtext:** “Connect AI assistants via Model Context Protocol”

This block always shows:

1. **MCP Server URL** — One line: `{window.location.origin}/api/mcp?apikey={YOUR_API_KEY}` (or the literal new token right after creation). **Copy** copies the full URL.

If the user has **at least one saved token** (`tokens.length > 0`), the UI **additionally** shows three labeled JSON snippets (same shape today; names differ only in labels):

- **Claude Desktop Configuration**
- **Cursor Configuration**
- **Generic MCP Client**

Each snippet is a **`mcpServers`** object with a single server key **`coding-agent`** and property **`url`** set to the same URL as above. Each block has its own **Copy** button.

If **no tokens exist yet**, only the URL row appears, plus helper text: *“Create an API token above to get started with MCP server configuration.”*

**Documentation link:** “See **full documentation**” → internal route `/docs/mcp-server` (renders [MCP_SERVER.md](./MCP_SERVER.md) via `app/docs/mcp-server/page.tsx`).

---

## How the templates map to real client setup

The UI generates URLs from **`window.location.origin`** (fallback string in SSR: `https://code.agenticassets.ai` in code). Replace with your deployment hostname when documenting for users.

**Important:** After you copy a snippet, **replace** `YOUR_API_KEY` with a real token unless you just created one and the UI substituted it.

### Recommended URL shape (matches UI)

```text
https://YOUR-DEPLOYMENT/api/mcp?apikey=YOUR_API_TOKEN
```

### Claude Desktop

Merge into the OS-specific `claude_desktop_config.json` under `mcpServers` (see [MCP_GUIDE.md](./MCP_GUIDE.md) for platform paths). The JSON emitted by the UI matches:

```json
{
  "mcpServers": {
    "coding-agent": {
      "url": "https://YOUR-DEPLOYMENT/api/mcp?apikey=YOUR_API_TOKEN"
    }
  }
}
```

Restart Claude Desktop after editing.

### Cursor

The in-app **Cursor Configuration** block uses the **same JSON** as Claude Desktop in `components/api-keys-dialog.tsx`. Some Cursor setups expect a root **`transport`** field for HTTP MCP or a different config filename depending on version—if your client fails to connect, compare with [MCP_GUIDE.md](./MCP_GUIDE.md) and [MCP_SERVER.md](./MCP_SERVER.md) and adjust for your Cursor version.

### Windsurf and other clients

Use the same **`url`**-based `mcpServers` entry where supported, or configure the equivalent “remote HTTP MCP” URL from the **MCP Server URL** line.

### Bearer header instead of query string

Supported by the server per [MCP_SERVER.md](./MCP_SERVER.md): send `Authorization: Bearer YOUR_API_TOKEN` if the client does not allow query parameters (better for avoiding tokens in URLs).

---

## Endpoints and source files (for maintainers)

| Concern | Location |
| --- | --- |
| API Keys dialog UI (external MCP section + tokens + curl) | `components/api-keys-dialog.tsx` |
| Entry point from user menu | `components/auth/sign-out.tsx` |
| Token create/list/delete API | `app/api/tokens/` (and related route handlers) |
| MCP HTTP handler | `app/api/mcp/route.ts` |
| Full protocol, tools, auth priority | [docs/MCP_SERVER.md](./MCP_SERVER.md) |
| End-user walkthrough (editors, prompts) | [docs/MCP_GUIDE.md](./MCP_GUIDE.md) |
| Rendered docs page | `app/docs/mcp-server/page.tsx` |

---

## Replicating this UX in another chat product

1. **Token lifecycle:** One-time display on create; list view shows only non-secret prefix + metadata.
2. **MCP section:** Always show canonical **MCP URL**; gate **full JSON presets** on “has at least one token” if you want parity with this app (optional).
3. **Copy affordances:** Label + **Copy** per block; use horizontally scrollable `<pre>` for long URLs on mobile (`overflow-x-auto`, small mono text).
4. **Cross-link** to long-form docs for tools, rate limits, and errors.

This keeps the in-product surface **short** while [MCP_SERVER.md](./MCP_SERVER.md) remains the **authoritative** reference for integration details.
