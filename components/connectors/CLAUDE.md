# Connectors Components

## Domain Purpose
UI for MCP connector management: CRUD operations, preset server selection, environment variable configuration, OAuth credential handling.

## Module Boundaries
- **Owns**: Connector dialog UI, form validation, accordion state, icon display
- **Delegates to**: `lib/actions/connectors.ts` for mutations, `lib/db/schema.ts` for Connector type, icon components for rendering

## Local Patterns
- **Dialog States**: list, preset selection, and form/edit flows are tracked via Jotai atoms
- **Accordion**: Preset servers collapsed/expanded for selection (Browserbase, Context7, Convex, Figma, HuggingFace, Linear, Notion, Orbis, Playwright, Supabase)
- **Env Vars**: Two-column input: key/value pairs, encrypted before storage
- **Mutations**: create, update, delete, and enable/disable flows are driven by server actions
- **Icon Mapping**: Icon component selected based on `connector.type` string

## Integration Points
- `lib/actions/connectors.ts` - Server actions for create/update/delete/toggle
- `components/connectors-provider.tsx` - Context for managing connector list state
- `components/task-form.tsx` - Shows "Configure MCP Servers" button to open dialog
- Jotai atoms in `lib/atoms/connector-dialog.ts` manage dialog view, editing state, presets, and env var visibility

## Key Files
- `manage-connectors.tsx` - Main dialog for CRUD views, preset selection, and env var management
- Dialog flow: list → presets/custom → configure → submit
- Real-time form validation for required fields, toggle visibility for sensitive values
