# app/repos

Repository browser with nested routing: commits, issues, and pull-request tabs.

## Domain Purpose
- Display GitHub repo metadata from live API: commit history, issues, PRs with CI/CD status
- Secondary browsing interface (primary: task pages in app/tasks)
- No local storage; fetch fresh data on each request

## Local Patterns
- **Nested routing**: Layout at `[owner]/[repo]/layout.tsx` with tab navigation; each tab in subdirectory
- **Page redirect**: `[owner]/[repo]/page.tsx` redirects to commits tab
- **Metadata generation**: `generateMetadata()` with dynamic owner/repo
- **Session-aware rendering**: pages can render without a session, but successful data loading depends on the downstream API auth state

## Directory Structure
```
app/repos/
├── new/page.tsx                      # Create new repository page
└── [owner]/[repo]/
    ├── layout.tsx                   # Shared layout + RepoLayout component
    ├── page.tsx                     # Redirect to commits
    ├── commits/page.tsx             # Component: RepoCommits
    ├── issues/page.tsx              # Component: RepoIssues
    └── pull-requests/page.tsx       # Component: RepoPullRequests
```

## Integration Points
- **GitHub API**: Commits, issues, PRs, check runs (via api/repos routes)
- **Task Association**: PR check endpoint maps PR to task
- **Authentication**: the page shell can render anonymously, but repo data comes from protected GitHub-backed API routes
- **Components**: `components/repo-[name].tsx` - receive owner, repo, user session

## Adding New Tabs
1. Create `app/repos/[owner]/[repo]/[tab-name]/page.tsx`
2. Create component `components/repo-[tab-name].tsx`
3. Add API route `app/api/repos/[owner]/[repo]/[tab-name]/route.ts`
4. Add to `tabs` array in `components/repo-layout.tsx`

## Key Files
- `new/page.tsx` - Create new repository page (shows repo templates)
- `[owner]/[repo]/layout.tsx` - Renders RepoLayout (tab bar) + children
- `[owner]/[repo]/page.tsx` - Redirect to commits
- Each tab imports data from `/api/repos/[owner]/[repo]/[tab]/`
