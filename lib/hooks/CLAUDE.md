# Hooks Module

## Domain Purpose
Client-side React hooks for data fetching, polling, and state management.

## Module Boundaries
- **Owns**: Hook logic, polling intervals, SWR integration, loading/error state
- **Delegates to**: SWR, native `fetch()`, and React state/effect primitives

## Local Patterns
- **SWR-based hooks**: hooks such as `useTask` and `useTaskMessages` use shared fetchers and refresh intervals instead of bespoke retry state machines
- **Polling**: refresh intervals are driven by SWR configuration where live updates are needed
- **Loading State**: rely on hook return shape (`isLoading`, `error`, `data`) instead of custom attempt counters

## Integration Points
- `components/task-page-client.tsx` - Display task data with live updates
- `app/tasks/[taskId]/page.tsx` - Task detail page shell

## Key Files
- `use-task.ts` - Task fetching with SWR polling
