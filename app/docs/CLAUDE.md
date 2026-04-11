# app/docs

Renders selected static markdown files from `docs/` as web pages using React Markdown with GFM support.

## Domain Purpose
- Serve platform documentation via web UI (setup guides, API references)
- Read markdown at build/request time via `readFileSync`
- Support GitHub Flavored Markdown (tables, strikethrough, task lists)

## Local Patterns
- **Explicit page routing**: each published doc page is implemented explicitly (for example `app/docs/mcp-server/page.tsx`)
- **Metadata template**: Export `metadata` object with title and description
- **Prose styling**: Container `max-w-4xl`, article with Tailwind `prose` classes and `dark:prose-invert`

## Rendering Plugins
- `remarkGfm` - GitHub Flavored Markdown (tables, strikethrough, task lists)
- `rehypeRaw` - Allow raw HTML (sanitized by CSP)

## Adding New Pages
1. Create the backing markdown file in `docs/`
2. Add a dedicated page under `app/docs/<slug>/page.tsx`
3. Read the markdown file with `readFileSync`, render with `ReactMarkdown`, and add metadata
4. Link the page from the relevant navigation surface

## Integration Points
- **Markdown files**: `docs/*.md` directory
- **React Markdown**: `react-markdown` npm package
- **Styling**: Tailwind `prose` + `prose-slate` + `dark:prose-invert`

## Performance
- Static rendering; cached by Next.js
- Build-time: Markdown files must exist when building
- Production: Changes require rebuild
