# app/api/repos

Repository metadata endpoints for commits, issues, pull requests, and PR-to-task lookups.

## Domain Purpose
- Fetch GitHub repo metadata from the live GitHub API for display in the repo browser (`app/repos/`)
- These routes depend on authenticated GitHub access through the server-side Octokit client
- Integrates with task system: check-task maps PR to task, close-PR returns task status

## Local Patterns
- **Dynamic routing**: `[owner]/[repo]/` structure matches GitHub org/repo naming
- **Pagination**: Default 30 items per page (commits endpoint)
- **Authenticated GitHub access**: callers need a valid session-backed GitHub connection
- **Error handling**: Static error messages, no token/path exposure

## Routes
- `[owner]/[repo]/commits/route.ts` - Get repo commits (30 per page)
- `[owner]/[repo]/issues/route.ts` - Get repo issues with optional filter
- `[owner]/[repo]/pull-requests/route.ts` - Get repo PRs (status, check-runs)
- `[owner]/[repo]/pull-requests/[pr_number]/check-task/route.ts` - Map PR → task
- `[owner]/[repo]/pull-requests/[pr_number]/close/route.ts` - Close PR (return task status)

## Integration Points
- **GitHub API**: `getOctokit()` from `@/lib/github/client` (Octokit REST v3)
- **Task system**: check-task returns taskId; close-PR updates task status
- **Session**: routes resolve the current user/session before accessing GitHub
- **Components**: Data consumed by `components/repo-[name].tsx` (commits, issues, pull-requests)

## Key Behaviors
- **Protected access**: unauthenticated callers or users without GitHub access receive auth errors
- **Check-runs**: PR endpoint includes CI/CD status from GitHub checks
- **Errors**: 401 when auth/GitHub access is missing, 404 when repo/PR is missing, 500 on upstream/API failures

## Key Files
- `[owner]/[repo]/commits/route.ts` - Fetch commits with pagination
- `[owner]/[repo]/issues/route.ts` - Fetch issues (filter by state, assignee, etc.)
- `[owner]/[repo]/pull-requests/route.ts` - Fetch PRs with check-run status
- Check-task and close-PR routes: task association logic
