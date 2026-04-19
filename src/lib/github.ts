import reposSnapshot from '../data/github-repos.json';
import profileSnapshot from '../data/github-profile.json';

export interface GithubRepo {
  name: string;
  fullName: string;
  description: string | null;
  htmlUrl: string;
  homepage: string | null;
  language: string | null;
  topics: string[];
  stargazersCount: number;
  forksCount: number;
  openIssuesCount: number;
  watchersCount: number;
  size: number;
  archived: boolean;
  fork: boolean;
  private: boolean;
  disabled: boolean;
  defaultBranch: string | null;
  license: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  pushedAt: string | null;
}

export interface GithubProfile {
  login: string;
  name: string | null;
  bio: string | null;
  avatarUrl: string | null;
  htmlUrl: string;
  location: string | null;
  company: string | null;
  blog: string | null;
  publicRepos: number;
  followers: number;
  following: number;
  createdAt: string | null;
  updatedAt: string | null;
  fetchedAt: string | null;
}

const { repos } = reposSnapshot as { fetchedAt: string; repos: GithubRepo[] };

export const githubProfile = profileSnapshot as GithubProfile;
export const githubRepos = repos;

export function findRepo(fullName: string): GithubRepo | undefined {
  return repos.find(
    (r) => r.fullName.toLowerCase() === fullName.toLowerCase(),
  );
}

const HIDDEN_REPO_PATTERNS = [/^fact_checker_ai$/i];

export function visibleRepos(): GithubRepo[] {
  return repos.filter((r) => {
    if (r.fork || r.archived || r.private) return false;
    if (r.size < 5) return false;
    if (HIDDEN_REPO_PATTERNS.some((re) => re.test(r.name))) return false;
    return true;
  });
}
