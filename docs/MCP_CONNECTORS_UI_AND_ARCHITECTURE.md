# MCP servers in the web UI: architecture and file map

This document explains how **user-configured MCP servers** (called **connectors** in code) work in this repository: the modal flows from your screenshots, toggles, environment variables, and how that configuration reaches the coding agents in the sandbox. It is separate from two other “MCP” topics in this repo:

| Topic | What it is | Main docs |
| --- | --- | --- |
| **Connectors (this doc)** | MCP servers the user adds in the app so **Claude Code / other agents** can call tools while running a task | This file |
| **Our MCP HTTP API** | Exposes this platform to **Claude Desktop, Cursor, etc.** (`/api/mcp`, tools like `create-task`) | [docs/MCP_SERVER.md](./MCP_SERVER.md), [docs/MCP_GUIDE.md](./MCP_GUIDE.md) |
| **API Keys dialog “MCP Server” section** | Copy/paste URLs and sample configs so **external** MCP clients can talk to **`/api/mcp`** using the user’s bearer token | `components/api-keys-dialog.tsx`, `/docs/mcp-server` |

---

## End-to-end behavior (what the screenshots represent)

1. **Opening the modal**  
   On the task composer, the cable icon opens **`ConnectorDialog`** (“MCP Servers”). A badge shows how many connectors have **`status === 'connected'`**.

2. **List view**  
   Each row is one saved connector: icon (from name/URL/command), name, optional description, **edit** (pencil), and a **Switch** (toggle).

3. **Toggle on/off**  
   The switch does **not** delete anything. It updates **`connectors.status`** to **`connected`** or **`disconnected`** via a server action. Only **`connected`** connectors are loaded when a task runs.

4. **Add flow**  
   **Add MCP Server** → preset grid (“Browserbase”, “Context7”, …) **or** **Add Custom MCP Server** → form.

5. **Form fields** (matches your copy: “Example MCP Server”, Remote vs Local, URL, Add Variable, Advanced Settings, Back, Add MCP Server)  
   - **Name** → `connectors.name`  
   - **Server type** → `connectors.type`: **`remote`** (HTTP/SSE URL) or **`local`** (STDIO command string)  
   - **Base URL** (`remote`) or **Command** (`local`)  
   - **Environment variables** → stored as encrypted JSON in **`connectors.env`**; key names like `Authorization` become **HTTP headers** for remote servers (see Claude agent mapping below)  
   - **Advanced Settings** (remote only, accordion): optional **OAuth Client ID** / **OAuth Client Secret** → `oauthClientId` / `oauthClientSecret` (secret encrypted)

6. **Persistence**  
   Create/update/delete use **Next.js Server Actions** (`lib/actions/connectors.ts`). Listing uses **`GET /api/connectors`** (session cookie), also consumed by **`ConnectorsProvider`**.

7. **Execution**  
   When a task runs, **`lib/tasks/process-task.ts`** loads **all connectors for the user with `status === 'connected'`**, decrypts `env` and secrets, and passes them to **`executeAgentInSandbox(..., mcpServers)`**. Each agent writes its own MCP config file inside the Vercel sandbox (for example Claude writes **`${PROJECT_DIR}/.mcp.json`**).

---

## How environment variables and “API keys” relate

- **Connectors UI env vars** are **not** the same row as **provider API keys** (Anthropic, OpenAI, …) stored in the **`keys`** table. They are **per-connector** secrets used when starting MCP transports (headers for HTTP MCP, `env` object for stdio).
- Values are **encrypted at rest** (`encrypt(JSON.stringify(env))` on write; decrypt + `JSON.parse` on read). See **`lib/actions/connectors.ts`** and **`app/api/connectors/route.ts`**.
- For **remote** MCP servers in **Claude**, **`lib/sandbox/agents/claude.ts`** maps each entry in **`connector.env`** to **`headers`** on the HTTP MCP entry. Optional **`oauthClientSecret`** is added as **`Authorization: Bearer …`** (and can overlap with manual env—implementation merges sources).

---

## Dialog state machine (why there are “back” arrows and multiple titles)

Views are **`list` | `presets` | `form`**, driven by Jotai atoms in **`lib/atoms/connector-dialog.ts`**:

- **`connectorDialogViewAtom`** — current panel  
- **`editingConnectorAtom`** — when set, form is in **edit** mode  
- **`selectedPresetAtom`** — preset picked from the grid (pre-fills URL/command and suggested env **keys**)  
- **`serverTypeAtom`**, **`envVarsAtom`**, **`visibleEnvVarsAtom`** — form UI state  

Implementation reference: **`components/connectors/manage-connectors.tsx`** (`ConnectorDialog`).

---

## Preset MCP servers (grid)

Constants live in **`PRESETS`** inside **`components/connectors/manage-connectors.tsx`** (Browserbase, Context7, Convex, Figma, Hugging Face, Linear, Notion, Orbis, Playwright, Supabase). Icons live under **`components/icons/`** (for example `orbis-icon.tsx`, `supabase-icon.tsx`).

---

## Exact file and folder index

| Area | Path |
| --- | --- |
| Main modal UI (list / presets / form, toggle, delete) | `components/connectors/manage-connectors.tsx` |
| Connector list context + `fetch('/api/connectors')` | `components/connectors-provider.tsx` |
| Dialog view + preset atoms | `lib/atoms/connector-dialog.ts` |
| Task form entry (cable button, badge count, dialog mount) | `components/task-form.tsx` |
| App shell: where `ConnectorsProvider` wraps the tree | `components/app-layout.tsx` |
| DB table **`connectors`** + Zod types | `lib/db/schema.ts` (`connectors`, `insertConnectorSchema`, `selectConnectorSchema`) |
| Server Actions: create, update, delete, toggle, `getConnectors` | `lib/actions/connectors.ts` |
| REST: **`GET /api/connectors`** (session; decrypted payload for UI) | `app/api/connectors/route.ts` |
| Task pipeline: fetch connected MCP servers + decrypt | `lib/tasks/process-task.ts` (search for `mcpServers`, `connectors`) |
| Agent dispatcher | `lib/sandbox/agents/index.ts` |
| Claude: **`.mcp.json`** from connectors | `lib/sandbox/agents/claude.ts` (`buildMcpJsonConfig`) |
| Codex / Copilot / Cursor / Gemini / OpenCode MCP wiring | `lib/sandbox/agents/codex.ts`, `copilot.ts`, `cursor.ts`, `gemini.ts`, `opencode.ts` |
| Task rows may store **`mcpServerIds`** for display/history | `lib/db/schema.ts` (`tasks.mcpServerIds`), **`components/task-details.tsx`** (loads connector names for IDs) |
| **Separate**: external-client MCP URL snippets in API Keys dialog | `components/api-keys-dialog.tsx` |
| Rendered doc for **`/api/mcp`** consumers | `docs/MCP_SERVER.md`, page `app/docs/mcp-server/page.tsx` |
| Connectors module notes | `components/connectors/CLAUDE.md`, `app/api/connectors/CLAUDE.md` |

---

## Building similar UX in another AI chat app

Minimal building blocks:

1. **Data model** — id, userId, display name, `local` vs `remote`, `command` vs `baseUrl`, encrypted `env` map, optional OAuth fields, **`connected` boolean or enum** for enable/disable without delete.
2. **API or Server Actions** — CRUD + toggle; always scope by **`userId`**; encrypt secrets on write.
3. **Client UI** — modal + multi-step state (list → pick preset/custom → form); optional preset table keyed by name/url/command.
4. **Runtime** — when launching the coding agent, query **only enabled connectors**, decrypt, and serialize to the MCP format your agent expects (stdio vs HTTP + headers).

---

## Copy deck reference (in-app strings)

The form’s instructional line is defined as **`DialogDescription`** when **`view === 'form'`** in **`manage-connectors.tsx`**:

> Allow agents to reference other apps and services for more context. For authentication, add headers like Authorization using environment variables below.

Placeholders include **`Example MCP Server`**, **`https://api.example.com`**, buttons **Add Variable**, **Advanced Settings**, **Back**, **Add MCP Server**, plus preset screen **Choose a preset or add a custom server** and list subtitle **Manage your Model Context Protocol servers.**
