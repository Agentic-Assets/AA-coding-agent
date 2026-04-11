# app/tasks

Task UI pages: list (index) and detail view with dynamic routing.

## Domain Purpose
- Display user's tasks in list view with filtering/sorting
- Show individual task detail: sandbox, agent execution, file editor, PR status
- The list page enforces auth on the server; the detail page is more client-driven and depends on downstream fetch/auth state

## Local Patterns
- **Mixed auth handling**: `/tasks` redirects on missing session; `/tasks/[taskId]` renders the page shell and lets client data fetching determine the final state
- **Server components**: Fetch user session + GitHub stars on server; pass to client components
- **Dynamic metadata**: Task detail page generates metadata from task title
- **Client-heavy**: Actual UI/interactions delegated to client components

## Routes
- `GET /tasks` - Task list page (requires auth)
- `GET /tasks/[taskId]` - Task detail page shell with dynamic metadata and client-driven data loading

## Directory Structure
```
app/tasks/
├── page.tsx              # List page → TasksListClient
├── [taskId]/
│   ├── page.tsx         # Detail page → TaskPageClient
│   ├── layout.tsx       # (if needed for detail view layout)
│   ├── loading.tsx      # Loading skeleton
│   └── not-found.tsx    # 404 fallback
```

## Integration Points
- **Session**: `getServerSession()` from `@/lib/session/get-server-session`
- **GitHub**: `getGitHubStars()` for UI display
- **Sandbox**: Max duration from `@/lib/db/settings` (user-specific > global > env)
- **Client components**: `TasksListClient` (list), `TaskPageClient` (detail)

## Key Behaviors
- **Redirect on no auth**: the list page redirects to `/` when user is null
- **Non-blocking render**: Server fetches all data in parallel, renders immediately
- **Skeleton loading**: `loading.tsx` shows spinner while page loads
- **Dynamic titles**: Detail page generates title from task object (if available)

## Key Files
- `page.tsx` - List page handler with auth check + stars fetch
- `[taskId]/page.tsx` - Detail page with dynamic metadata generation
- Both delegate UI rendering to respective client components
