#!/usr/bin/env tsx
/**
 * Fetch R3izorr's public GitHub profile and repo list and write normalized
 * snapshots to src/data/github-profile.json and src/data/github-repos.json.
 *
 * Pass a token via GITHUB_TOKEN env var for higher rate limits.
 *
 *   pnpm run fetch:github
 *   GITHUB_TOKEN=ghp_xxx pnpm run fetch:github
 *
 * If the fetch fails, existing committed snapshots are left untouched.
 */

import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const USER = 'R3izorr';
const OUT_DIR = resolve(process.cwd(), 'src/data');
const TOKEN = process.env['GITHUB_TOKEN'];

const headers: Record<string, string> = {
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
  'User-Agent': 'r3izorr-portfolio-build',
};
if (TOKEN) headers['Authorization'] = `Bearer ${TOKEN}`;

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`${url} -> ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

interface RawUser {
  login: string;
  name: string | null;
  bio: string | null;
  avatar_url: string;
  html_url: string;
  location: string | null;
  company: string | null;
  blog: string | null;
  public_repos: number;
  followers: number;
  following: number;
  created_at: string;
  updated_at: string;
}

interface RawRepo {
  name: string;
  full_name: string;
  description: string | null;
  html_url: string;
  homepage: string | null;
  language: string | null;
  topics?: string[];
  stargazers_count: number;
  forks_count: number;
  open_issues_count: number;
  watchers_count: number;
  size: number;
  archived: boolean;
  fork: boolean;
  private: boolean;
  disabled: boolean;
  default_branch: string | null;
  license: { spdx_id: string | null } | null;
  created_at: string;
  updated_at: string;
  pushed_at: string;
}

async function main() {
  const fetchedAt = new Date().toISOString();

  const user = await get<RawUser>(`https://api.github.com/users/${USER}`);
  const profile = {
    login: user.login,
    name: user.name,
    bio: user.bio,
    avatarUrl: user.avatar_url,
    htmlUrl: user.html_url,
    location: user.location,
    company: user.company,
    blog: user.blog,
    publicRepos: user.public_repos,
    followers: user.followers,
    following: user.following,
    createdAt: user.created_at,
    updatedAt: user.updated_at,
    fetchedAt,
  };

  const rawRepos = await get<RawRepo[]>(
    `https://api.github.com/users/${USER}/repos?per_page=100&sort=updated&type=owner`,
  );
  const repos = rawRepos.map((r) => ({
    name: r.name,
    fullName: r.full_name,
    description: r.description,
    htmlUrl: r.html_url,
    homepage: r.homepage,
    language: r.language,
    topics: r.topics ?? [],
    stargazersCount: r.stargazers_count,
    forksCount: r.forks_count,
    openIssuesCount: r.open_issues_count,
    watchersCount: r.watchers_count,
    size: r.size,
    archived: r.archived,
    fork: r.fork,
    private: r.private,
    disabled: r.disabled,
    defaultBranch: r.default_branch,
    license: r.license?.spdx_id ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    pushedAt: r.pushed_at,
  }));
  repos.sort((a, b) => (b.pushedAt ?? '').localeCompare(a.pushedAt ?? ''));

  await writeFile(
    `${OUT_DIR}/github-profile.json`,
    `${JSON.stringify(profile, null, 2)}\n`,
  );
  await writeFile(
    `${OUT_DIR}/github-repos.json`,
    `${JSON.stringify({ fetchedAt, repos }, null, 2)}\n`,
  );
  console.log(
    `Wrote ${repos.length} repos and profile for @${user.login} at ${fetchedAt}`,
  );
}

main().catch((err) => {
  console.error('[fetch-github-data] failed:', err);
  console.error(
    '[fetch-github-data] keeping existing snapshots (they will be used for build).',
  );
  process.exit(1);
});
