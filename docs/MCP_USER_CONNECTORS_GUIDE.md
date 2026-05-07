# User connectors (MCP Servers): guide and UI behavior

**User connectors** are MCP servers **you save in this app** so that **coding agents running inside tasks** (in the Vercel sandbox) can call external tools—Linear, Supabase, Context7, your own HTTP MCP server, etc.

This is **not** the same as connecting **Claude Desktop / Cursor** *to this platform* via `/api/mcp`. That **inbound** flow is documented in [MCP_GUIDE.md](./MCP_GUIDE.md) and [MCP_SERVER.md](./MCP_SERVER.md).

---

## Concepts at a glance

| Name in the UI | Row in the database | What it does |
| --- | --- | --- |
| **MCP Servers** (modal title) | `connectors` table | Stores each server’s name, **remote vs local** type, URL or CLI command, optional **env** map (encrypted), optional OAuth fields, and **connected / disconnected** status. |
| Toggle **on** | `status = 'connected'` | Connector is loaded when a task runs the agent (see execution below). |
| Toggle **off** | `status = 'disconnected'` | Still saved; **not** injected into the sandbox for new runs. |

---

## Where users open the UI

1. Open the **task composer** (home or task page).
2. Click the **cable** icon next to the submit area (**aria-label:** “MCP Servers”).
3. A **badge** on the icon shows how many connectors are **`connected`** (not total count).

**Code:** `components/task-form.tsx` (`ConnectorDialog`, `useConnectors()`, `connectedCount`).

The list of connectors is loaded globally via **`ConnectorsProvider`** (`components/connectors-provider.tsx`), which **`GET /api/connectors`** when mounted.

---

## How the modal looks and behaves (three views)

Implementation: **`components/connectors/manage-connectors.tsx`** (`ConnectorDialog`). State views: **`list` | `presets` | `form`** (Jotai: **`lib/atoms/connector-dialog.ts`**).

**Shell:** Wide dialog — `DialogContent` with `w-[800px] max-w-[90vw] max-h-[80vh]`, scrollable body regions (`max-h-[60vh]` for inner panels). Uses **shadcn** `Dialog`, `Card`, `Switch`, `Button`, `Input`, `RadioGroup`, `Accordion`.

### View A — List (“MCP Servers”)

- **Title:** “MCP Servers”
- **Subtitle:** “Manage your Model Context Protocol servers.”
- **Rows:** Each connector is a **horizontal Card**: optional **brand icon** (heuristic from name / URL / command — Browserbase, Context7, Orbis, etc., or generic **Server** icon), **title** (name), optional **description** line, **pencil** (edit), **Switch** (on = connected).
- **Loading:** Skeleton cards (pulsing placeholders).
- **Empty:** Centered message — no servers configured yet.
- **Footer:** Right-aligned primary button **“Add MCP Server”**.

**Toggle:** Flipping the switch calls the server action **`toggleConnectorStatus`** (`lib/actions/connectors.ts`). It does **not** delete the connector.

### View B — Presets (“Add MCP Server”)

- **Title:** “Add MCP Server” with **back** arrow (returns to list).
- **Subtitle:** “Choose a preset or add a custom server.”
- **Grid:** Three columns of tappable tiles — large **logo** (48px), preset **name** below.
- **Footer:** Full-width **outline** button **“Add Custom MCP Server”** (opens form without a preset).

Presets are defined in **`PRESETS`** in the same file (names and defaults today):

| Preset | Type | Default URL or command |
| --- | --- | --- |
| Browserbase | local | `npx @browserbasehq/mcp` (+ suggested env keys) |
| Context7 | remote | `https://mcp.context7.com/mcp` |
| Convex | local | `npx -y convex@latest mcp start` |
| Figma | remote | `https://mcp.figma.com/mcp` |
| Hugging Face | remote | `https://hf.co/mcp` |
| Linear | remote | `https://mcp.linear.app/sse` |
| Notion | remote | `https://mcp.notion.com/mcp` |
| Orbis | remote | `https://www.phdai.ai/api/mcp/universal` (+ suggested `Authorization` env key) |
| Playwright | local | `npx -y @playwright/mcp@latest` |
| Supabase | remote | `https://mcp.supabase.com/mcp` |

Icons live under **`components/icons/`** (e.g. `orbis-icon.tsx`, `supabase-icon.tsx`).

### View C — Form (add or edit)

- **Title:** “MCP Servers” when adding from scratch, or **“Edit MCP Server”** when editing; **back** arrow behavior differs (from presets vs from edit — see atoms **`goBackFromFormAtom`**).
- **Subtitle (form view):**  
  *“Allow agents to reference other apps and services for more context. For authentication, add headers like Authorization using environment variables below.”*

**Fields:**

1. **Name** — placeholder “Example MCP Server”.
2. **Server type** — **Remote (HTTP/SSE)** vs **Local (STDIO)** via `RadioGroup`. Hidden when a **preset** is selected or certain edit flows (preset locks type/command/url).
3. **Base URL** (remote) — placeholder `https://api.example.com`; required for remote.
4. **Command** (local) — full CLI string (e.g. `npx …`); helper text explains it includes all arguments.
5. **Environment Variables** — label “Environment Variables (optional)” unless the preset ships **`envKeys`** (then keys can be fixed rows). **“+ Add Variable”** appends key/value rows. Values use **password** input with **eye** toggle per row.
6. **Advanced Settings** — **Accordion** (remote only): optional **OAuth Client ID** and **OAuth Client Secret**.

**Footer:** **Back** (outline) + primary **“Add MCP Server”** or **“Save Changes”**; when **editing**, a **Delete** button opens a confirmation dialog.

On submit, the form wraps **`createConnector`** or **`updateConnector`** server actions with hidden fields: `type`, merged `env` JSON, preset `command`/`baseUrl`, and `id` when editing.

---

## Data storage and security

- **Table:** `connectors` in **`lib/db/schema.ts`** (`name`, `type`, `baseUrl`, `command`, `env`, `oauthClientId`, `oauthClientSecret`, `status`, timestamps, `userId`).
- **Secrets:** `env` is stored as **encrypted** JSON string; OAuth secret encrypted. **`lib/actions/connectors.ts`** encrypts on write; **`GET /api/connectors`** (`app/api/connectors/route.ts`) decrypts for the signed-in user only.

---

## How connectors reach the agent at runtime

1. **`lib/tasks/process-task.ts`** loads connectors where **`status === 'connected'`** for the task’s user, decrypts `env` / OAuth secret, and passes **`mcpServers`** into **`executeAgentInSandbox`**.
2. **`lib/sandbox/agents/index.ts`** forwards **`mcpServers`** to every agent implementation (`claude`, `codex`, `copilot`, `cursor`, `gemini`, `opencode`).
3. Each agent writes **its own** MCP configuration format inside the sandbox (examples):
   - **Claude:** **`${PROJECT_DIR}/.mcp.json`** — **`buildMcpJsonConfig`** in **`lib/sandbox/agents/claude.ts`**: local → `stdio` + `command`/`args`/`env`; remote → `http` + `url` + **`headers`** built from **`env`** key/value pairs (so `Authorization` in env becomes a header) plus optional OAuth-derived headers.
   - **Cursor:** **`~/.cursor/mcp.json`** — **`cursor.ts`**
   - **Copilot:** **`~/.copilot/mcp-config.json`** — **`copilot.ts`**
   - **Codex:** **`~/.codex/config.toml`** — **`codex.ts`**
   - **Gemini / OpenCode:** agent-specific config objects — **`gemini.ts`**, **`opencode.ts`**

Product docs sometimes emphasize Claude + `.mcp.json`; the dispatcher still passes the same connector list to other agents where implemented.

---

## Task detail UI (optional)

If a task record stores **`mcpServerIds`**, **`components/task-details.tsx`** can resolve names for display by fetching connectors and filtering — useful for “which MCPs were attached?” style history.

---

## File index (maintainers)

| Topic | Path |
| --- | --- |
| Modal UI | `components/connectors/manage-connectors.tsx` |
| Connector context / fetch | `components/connectors-provider.tsx` |
| Dialog view state (Jotai) | `lib/atoms/connector-dialog.ts` |
| Task form entry (cable button) | `components/task-form.tsx` |
| Provider wrap | `components/app-layout.tsx` |
| CRUD + toggle actions | `lib/actions/connectors.ts` |
| List API | `app/api/connectors/route.ts` |
| Schema | `lib/db/schema.ts` (`connectors`) |
| Task pipeline load | `lib/tasks/process-task.ts` |
| Claude MCP JSON | `lib/sandbox/agents/claude.ts` |
| Other agents | `lib/sandbox/agents/*.ts` |
| Module notes | `components/connectors/CLAUDE.md`, `app/api/connectors/CLAUDE.md` |

---

## Building similar UX elsewhere

- Persist **per-user** connector rows with **encrypt-at-rest** for env and secrets.
- Use **connected/disconnected** (or boolean **enabled**) so users can disable without deleting.
- Provide **presets** as shortcuts that pre-fill URL/command and suggested env **keys**.
- At agent startup, serialize only **enabled** connectors into the MCP config format your runner expects (`stdio` vs `http` + headers).
