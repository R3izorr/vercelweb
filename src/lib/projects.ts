import projectsMeta from '../data/projects.json';
import { findRepo, type GithubRepo } from './github';

export interface ProjectMeta {
  slug: string;
  repo: string;
  title: string;
  summary: string;
  description?: string;
  featured: boolean;
  order?: number;
  category: string;
  stack: string[];
  tags: string[];
  links: { github?: string; demo?: string; docs?: string };
  status?: 'active' | 'archived' | 'prototype' | 'school';
  startDate?: string;
  updatedAt?: string;
  screenshots?: { src: string; alt: string }[];
}

export interface EnrichedProject extends ProjectMeta {
  github?: GithubRepo;
  primaryLanguage?: string | null;
  stars?: number;
  forks?: number;
  pushedAt?: string | null;
}

export function getProjects(): EnrichedProject[] {
  return (projectsMeta as ProjectMeta[])
    .map((p) => {
      const gh = findRepo(p.repo);
      return {
        ...p,
        github: gh,
        primaryLanguage: gh?.language ?? null,
        stars: gh?.stargazersCount ?? 0,
        forks: gh?.forksCount ?? 0,
        pushedAt: gh?.pushedAt ?? null,
        links: {
          github: p.links.github ?? gh?.htmlUrl,
          ...p.links,
        },
      };
    })
    .sort((a, b) => {
      const ao = a.featured ? 0 : 1;
      const bo = b.featured ? 0 : 1;
      if (ao !== bo) return ao - bo;
      return (a.order ?? 999) - (b.order ?? 999);
    });
}

export function getFeaturedProjects(): EnrichedProject[] {
  return getProjects().filter((p) => p.featured);
}

export function getProjectBySlug(slug: string): EnrichedProject | undefined {
  return getProjects().find((p) => p.slug === slug);
}
