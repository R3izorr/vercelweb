# Portfolio Website Plan

## Summary

Build a static personal portfolio for Chien Nguyen / R3izorr:

- Main portfolio landing page with intro, GitHub projects, featured projects, skills, and contact links.
- Projects section with an index and dedicated project pages.
- CTF writeup section with an index, category/tag browsing, and individual writeup pages.
- Markdown/MDX-first content so projects and writeups can be expanded without touching route code.
- GitHub-backed project metadata where useful, with local overrides for descriptions, screenshots, and featured status.

The site should present R3izorr as a Computer Science student at NTU Singapore and aspiring cybersecurity engineer focused on reverse engineering, pwn, and CTFs.

## Reference Repo Findings

Reference repo inspected: `https://github.com/ZTzTopia/site`, cloned to `/tmp/ztztopia-site`.

Key structure:

```text
/
├── astro.config.mjs
├── package.json
├── tsconfig.json
├── public/
│   └── favicon.svg
└── src/
    ├── assets/
    ├── components/
    │   ├── Core/
    │   ├── TableOfContent/
    │   ├── Activity/
    │   ├── Header.astro
    │   ├── Footer.astro
    │   ├── Projects.astro
    │   ├── CardEvent.astro
    │   └── CardChallenge.astro
    ├── data/
    │   ├── projects.json
    │   ├── experiences.json
    │   └── writeups/
    ├── layouts/
    │   ├── BaseLayout.astro
    │   ├── PageLayout.astro
    │   └── BlogLayout.astro
    ├── pages/
    │   ├── index.astro
    │   ├── projects.astro
    │   ├── components.astro
    │   ├── robots.txt.ts
    │   └── writeups/
    ├── plugins/rehype/
    ├── styles/global.css
    ├── transformers/code-snippet.ts
    ├── utils/
    └── content.config.ts
```

Routing and content:

- Astro static output.
- `src/content.config.ts` defines collections for `projects`, `experiences`, `events`, and `challenges`.
- Projects come from `src/data/projects.json`.
- Writeups are loaded from `src/data/writeups` using glob loaders:
  - Events: `*/*/*.{md,mdx}`
  - Challenges: `*/*/*/*/*.{md,mdx}`
- Writeup routes are nested by year, event, category, and challenge:
  - `/writeups`
  - `/writeups/[year]`
  - `/writeups/[year]/[event]`
  - `/writeups/[year]/[event]/[category]`
  - `/writeups/[year]/[event]/[category]/[challenge]`
  - `/writeups/tags`
  - `/writeups/tags/[tag]`
  - `/writeups/_categories`
  - `/writeups/_categories/[category]`
- Individual writeup pages use `BlogLayout`, rendered MD/MDX content, generated headings, and a table of contents.
- SEO uses `astro-seo`, canonical URL from `Astro.site`, OpenGraph/Twitter metadata, JSON-LD, sitemap, and robots route.

Styling/components:

- Tailwind CSS v4 through `@tailwindcss/vite`.
- Flexoki color system in `src/styles/global.css`.
- Light/dark theme controlled by `ThemeProvider` and `ThemeSelect`.
- Reusable primitive components under `components/Core`: card, button, badge, chip, link, prose.
- Card grids use helper utilities to keep rounded edges clean across responsive columns.
- Header is sticky, responsive, and active-route aware.
- Blog pages include desktop and mobile table-of-content components.

Deployment setup:

- `output: 'static'`.
- `@astrojs/sitemap` and `astro-compress`.
- Build script runs `astro check && astro build`.
- No Vercel-specific config file in the reference repo.

## R3izorr GitHub Findings

Profile:

- Name: Chien Nguyen.
- Profile README says: “Hi, I'm Chris”; Computer Science at NTU Singapore; aspiring cybersecurity engineer; interested in reverse engineering and CTFs.
- Bio: `~06, just want to be good`.
- Public repos: 9.
- Location field: `viet`.
- LinkedIn from profile README: `https://www.linkedin.com/in/tr%E1%BA%A7n-chi%E1%BA%BFn-nguy%E1%BB%85n-951534252/`.

Repositories inspected:

| Repo | Notes | Stack signal |
| --- | --- | --- |
| `CTF_writeup` | Active writeup repo. Focus on rev and pwn. Contains many Markdown writeups and challenge assets. | Markdown, HTML, Python, C, binaries |
| `blog` | Minimal Next.js/MDX blog template with posts under `app/blog/posts`. | Next.js, TypeScript, MDX |
| `home-net-drift-monitor` | Python scanner/reporting project with modules for scanner, diff, risk, storage, PDF report. | Python |
| `sc2006-proj` | Hawker Opportunity Score Platform. Full-stack project with Vite React frontend, FastAPI backend, geospatial data, auth, AI assistant. | TypeScript, React, Vite, Python, FastAPI, Leaflet, Tailwind |
| `SC2006-Website` | Earlier/alternate Hawker Opportunity Score implementation with Next.js frontend and Express/Prisma backend. | TypeScript, Next.js, Express, Prisma, PostgreSQL |
| `Checksum-.text-in-androidNDK` | Native ELF `.text` checksum verifier for Android NDK tamper/hooking detection. | C++ |
| `SC2002-GRP5` | NTU SC2002 Java BTO management system. MVC-ish Java CLI app with reports, data, Javadocs, screenshots. | Java |
| `R3izorr` | GitHub profile README. | Markdown |
| `fact_checker_AI` | Placeholder repo, only README at inspection time. | None yet |

Likely featured projects:

- `CTF_writeup`
- `sc2006-proj`
- `Checksum-.text-in-androidNDK`
- `home-net-drift-monitor`
- Optional secondary: `SC2002-GRP5`, `blog`

CTF writeup repo observations:

- Current writeups are mostly `README.md` files nested by event/category/challenge.
- Categories include `pwn`, `PWN`, `rev`, `Rev`, `OSINT`, `exploit`, and some irregular paths such as `New folder`, single-folder event writeups, and duplicated nested challenge folders.
- Several writeups include challenge source, solves, Docker files, binaries, libc/ld files, flags, and exploit scripts.
- The portfolio should import or migrate writeup Markdown but avoid publishing raw flags/challenge binaries unless explicitly desired.

## Proposed Tech Stack

Use Astro, matching the reference repo where useful.

- Astro 5, static output.
- TypeScript strict mode.
- Tailwind CSS v4.
- Astro content collections for projects and writeups.
- MD/MDX for long-form writeups.
- `astro-icon` for Lucide icons.
- `@astrojs/sitemap` and `astro-seo` for SEO.
- `astro-compress` for static optimization.
- Shiki syntax highlighting through Astro markdown config.
- Build-time GitHub API fetch script for public repo metadata.

Why Astro:

- Matches reference architecture.
- Strong static-site fit for portfolio/writeups.
- Clean file-based routes.
- Good MD/MDX content ergonomics.
- Simple Vercel deployment with no server requirement.

## Proposed Project Structure

```text
/
├── README.md
├── astro.config.mjs
├── package.json
├── tsconfig.json
├── src/
│   ├── assets/
│   │   ├── avatar-placeholder.svg
│   │   └── project-placeholders/
│   ├── components/
│   │   ├── Core/
│   │   │   ├── Badge.astro
│   │   │   ├── Button.astro
│   │   │   ├── Card.astro
│   │   │   ├── Chip.astro
│   │   │   ├── Link.astro
│   │   │   └── Prose.astro
│   │   ├── TableOfContent/
│   │   │   ├── MobileTableOfContent.astro
│   │   │   ├── TableOfContent.astro
│   │   │   └── TableOfContentList.astro
│   │   ├── Breadcrumb.astro
│   │   ├── ContactLinks.astro
│   │   ├── FeaturedProjects.astro
│   │   ├── Footer.astro
│   │   ├── GitHubProjects.astro
│   │   ├── Header.astro
│   │   ├── ProjectCard.astro
│   │   ├── ProjectHero.astro
│   │   ├── SkillsGrid.astro
│   │   ├── ThemeProvider.astro
│   │   ├── ThemeSelect.astro
│   │   ├── WriteupCard.astro
│   │   └── WriteupFilters.astro
│   ├── content.config.ts
│   ├── data/
│   │   ├── github-profile.json
│   │   ├── github-repos.json
│   │   ├── links.json
│   │   ├── projects.json
│   │   └── skills.json
│   ├── content/
│   │   ├── projects/
│   │   │   ├── ctf-writeup.mdx
│   │   │   ├── sc2006-proj.mdx
│   │   │   ├── checksum-text-android-ndk.mdx
│   │   │   └── home-net-drift-monitor.mdx
│   │   └── writeups/
│   │       ├── 2026/
│   │       │   └── midnightctf-2026/
│   │       │       └── pwn/
│   │       │           └── heapnote-ic.mdx
│   │       └── 2025/
│   │           └── imaginaryctf-2025/
│   │               └── rev/
│   │                   └── nimrod.mdx
│   ├── layouts/
│   │   ├── BaseLayout.astro
│   │   ├── BlogLayout.astro
│   │   └── PageLayout.astro
│   ├── lib/
│   │   ├── github.ts
│   │   ├── projects.ts
│   │   ├── seo.ts
│   │   └── writeups.ts
│   ├── pages/
│   │   ├── 404.astro
│   │   ├── index.astro
│   │   ├── projects/
│   │   │   ├── index.astro
│   │   │   └── [slug].astro
│   │   ├── robots.txt.ts
│   │   ├── sitemap.xml.ts
│   │   └── writeups/
│   │       ├── [...page].astro
│   │       ├── [year]/
│   │       │   ├── index.astro
│   │       │   └── [event]/
│   │       │       ├── index.astro
│   │       │       └── [category]/
│   │       │           ├── index.astro
│   │       │           └── [slug].astro
│   │       ├── categories/
│   │       │   ├── index.astro
│   │       │   └── [category].astro
│   │       └── tags/
│   │           ├── index.astro
│   │           └── [tag].astro
│   ├── scripts/
│   │   ├── fetch-github-data.ts
│   │   └── normalize-writeups.ts
│   ├── styles/
│   │   └── global.css
│   ├── transformers/
│   │   └── code-snippet.ts
│   └── utils/
│       ├── content.ts
│       ├── format.ts
│       ├── markdown.ts
│       └── path.ts
└── public/
    ├── favicon.svg
    └── screenshots/
        ├── ctf-writeup.svg
        ├── sc2006-proj.svg
        ├── checksum-text-android-ndk.svg
        └── home-net-drift-monitor.svg
```

## Page / Routes Plan

Main:

- `/`  
  Landing page with intro, featured projects, GitHub activity/project snapshot, skills, recent writeups, and contact links.

Projects:

- `/projects`  
  All selected projects, filters by stack/category, GitHub metadata, and featured markers.
- `/projects/[slug]`  
  Dedicated project detail page with summary, stack, links, screenshots/placeholders, GitHub stats, and longer writeup.

Writeups:

- `/writeups`  
  Paginated index of CTF events/writeups.
- `/writeups/[year]`  
  Year archive.
- `/writeups/[year]/[event]`  
  Event page listing challenges.
- `/writeups/[year]/[event]/[category]`  
  Category page for an event.
- `/writeups/[year]/[event]/[category]/[slug]`  
  Individual writeup.
- `/writeups/categories`  
  All categories.
- `/writeups/categories/[category]`  
  All writeups in a category.
- `/writeups/tags`  
  All tags.
- `/writeups/tags/[tag]`  
  All writeups with a tag.

Utility:

- `/404`
- `/robots.txt`
- sitemap generated by Astro integration or route.

## Component Plan

Core primitives:

- `Button`, `Card`, `Badge`, `Chip`, `Link`, `Prose`.
- Keep reference-style small components and typed props.

Layout:

- `BaseLayout`: HTML shell, SEO, theme provider, header, footer, breadcrumbs.
- `PageLayout`: constrained general content layout.
- `BlogLayout`: article layout with table of contents.

Navigation:

- `Header`: Home, Projects, Writeups, Contact anchor.
- `Footer`: GitHub, LinkedIn, email/contact, optional CTF profile links.
- `Breadcrumb`: route-derived breadcrumbs.

Portfolio:

- `FeaturedProjects`: hand-picked high-signal projects.
- `GitHubProjects`: GitHub repo metadata grid.
- `ProjectCard`: compact project card.
- `ProjectHero`: project detail header.
- `SkillsGrid`: grouped stack/skills.
- `ContactLinks`: links with icons.

Writeups:

- `WriteupCard`: challenge/event card with category, event, date, tags.
- `WriteupFilters`: category/tag/year controls.
- `TableOfContent`: reuse reference pattern.

## Project Content Model

Use a local `projects` collection or JSON-backed collection with GitHub enrichment.

Suggested project frontmatter/schema:

```ts
{
  slug: string;
  repo: string; // "R3izorr/sc2006-proj"
  title: string;
  summary: string;
  description?: string;
  featured: boolean;
  order?: number;
  category: "ctf" | "security" | "web" | "systems" | "school" | "tooling";
  stack: string[];
  tags: string[];
  links: {
    github?: string;
    demo?: string;
    docs?: string;
  };
  screenshots: {
    src: string;
    alt: string;
  }[];
  status?: "active" | "archived" | "prototype" | "school";
  startDate?: string;
  updatedAt?: string;
}
```

GitHub-enriched fields:

- repo name
- description
- primary language
- stars
- forks
- pushed date
- repository URL
- topics when available

Local-only fields:

- improved title/summary
- featured/order
- screenshots/placeholders
- stack corrections
- project narrative
- privacy-safe notes

Initial project entries:

- `ctf-writeup`
- `sc2006-proj`
- `checksum-text-android-ndk`
- `home-net-drift-monitor`
- `sc2002-grp5`
- `blog`

Keep `fact_checker_AI` hidden until it has real content.

## CTF Writeup Content Model

Use Astro content collections with MD/MDX.

Recommended path:

```text
src/content/writeups/{year}/{event}/{category}/{slug}.mdx
```

Suggested frontmatter/schema:

```ts
{
  title: string;
  description?: string;
  event: string;
  year: number;
  category: "web" | "crypto" | "pwn" | "rev" | "forensics" | "misc" | "osint";
  tags: string[];
  difficulty?: "easy" | "medium" | "hard" | "insane";
  points?: number;
  solves?: number;
  date?: string;
  sourceRepo?: string;
  sourcePath?: string;
  challengeUrl?: string;
  draft?: boolean;
  featured?: boolean;
  published?: boolean;
}
```

Migration strategy from `R3izorr/CTF_writeup`:

- Normalize event names to slugs.
- Normalize category casing:
  - `PWN`, `pwn`, `exploit` -> `pwn` or `web` depending on challenge.
  - `Rev`, `rev` -> `rev`.
  - `OSINT` -> `osint`.
- Convert nested `README.md` files into `.mdx` challenge files.
- Add frontmatter manually or with a helper script.
- Exclude raw binaries, `flag.txt`, libc/ld artifacts, Docker assets, and solve scripts from public site unless intentionally linked.
- Link back to source repo/path instead of copying every challenge artifact.
- Review writeups that include flags before publishing.

## Styling / Design Direction

Direction:

- Technical, compact, CTF-oriented.
- Keep reference repo’s simple card/grid rhythm and MDX readability.
- Use dark/light mode.
- Use a restrained terminal/security feel without turning the page into a gimmick.
- Avoid a marketing landing page. First screen should immediately identify the person, focus, featured work, and links.

Visual system:

- Tailwind utilities.
- Flexoki-inspired neutral base with category accent colors.
- Max-width readable layout like reference (`max-w-screen-md` for text-heavy pages).
- Wider grid only where project screenshots need space.
- Cards with small radius, thin borders, and stable responsive grids.
- Placeholder screenshots as clean SVG/code-window frames until real screenshots are provided.

Content tone:

- Direct and technical.
- Focus on security, reverse engineering, pwn, systems, and full-stack school projects.
- Avoid overclaiming on placeholder or unfinished repos.

## GitHub Data Strategy

Use a build-time fetch script:

```text
src/scripts/fetch-github-data.ts
```

Behavior:

- Fetch `https://api.github.com/users/R3izorr`.
- Fetch `https://api.github.com/users/R3izorr/repos?per_page=100&sort=updated&type=owner`.
- Optionally fetch languages per selected repo.
- Write normalized snapshots:
  - `src/data/github-profile.json`
  - `src/data/github-repos.json`
- Site reads local JSON during build.

Reasons:

- Static site remains fast and deployable anywhere.
- Avoid client-side GitHub rate limits.
- Build remains deterministic if snapshots are committed.
- Can run manually before deploy or as `prebuild`.

Fallback:

- If GitHub API fails during build, use committed JSON snapshots.

Selection rules:

- Exclude forks unless explicitly included.
- Exclude empty/placeholder repos from featured sections.
- Use local `projects.json` as the source of truth for featured/order.
- Merge GitHub metadata onto local project records by `repo`.

## Deployment Assumptions

- Deploy as a static Astro site.
- Target hosting: Vercel unless user chooses GitHub Pages or another host.
- No backend required.
- `site` in `astro.config.mjs` needs final domain.
- GitHub API is public-only unless a token is added for higher rate limits.
- No new GitHub repository is required yet because `/home/kuri/vercelweb` exists locally.
- If a new GitHub repo should be created later, needed inputs:
  - repository name
  - public/private
  - target owner/account
  - preferred default branch
  - deployment target/domain

## Implementation Plan

1. Bootstrap Astro project in `/home/kuri/vercelweb`.
2. Add dependencies matching the reference stack: Astro, TypeScript, Tailwind, `astro-icon`, sitemap, SEO, compression.
3. Add base config: `astro.config.mjs`, `tsconfig.json`, scripts, static output, sitemap, markdown highlighting.
4. Create global styles, theme provider/select, and core primitives.
5. Build layouts: `BaseLayout`, `PageLayout`, `BlogLayout`.
6. Create profile/link/skills data files.
7. Create GitHub fetch script and initial JSON snapshots.
8. Define content collections for projects and writeups.
9. Add project content pages for initial featured projects.
10. Build home page with intro, featured projects, skills, contact links, recent writeups.
11. Build projects index and project detail routes.
12. Normalize a small starter set of CTF writeups from `CTF_writeup` into MDX.
13. Build writeup index, category pages, tag pages, event pages, and individual writeup pages.
14. Add SEO metadata, robots, sitemap, OpenGraph defaults.
15. Add screenshot placeholders and public assets.
16. Update README with setup, content authoring, GitHub data refresh, and deployment notes.
17. Run formatting, linting/checking, and build.
18. Fix issues found by checks.

## Open Questions / Blockers

- Confirm preferred public name: `Chien Nguyen`, `Chris`, `R3izorr`, or a combination.
- Confirm contact email to publish. GitHub profile email is not public.
- Confirm final domain for `astro.config.mjs`.
- Confirm whether CTF flags should be hidden, removed, blurred, or published as-is.
- Confirm whether to migrate all existing CTF writeups now or start with a curated subset.
- Confirm whether raw challenge assets/binaries should be hosted, linked to GitHub, or excluded.
- Confirm if `blog` should be merged into this portfolio or kept separate.
- Confirm whether `SC2006-Website` and `sc2006-proj` are separate projects or one evolution/history entry.
- No GitHub repository creation is needed yet. If publishing to GitHub is required, repo ownership/name/visibility are needed.
