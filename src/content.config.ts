import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const CATEGORIES = [
  'pwn',
  'rev',
  'web',
  'crypto',
  'forensics',
  'osint',
  'misc',
] as const;

const projects = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/projects' }),
  schema: z.object({
    slug: z.string().optional(),
    repo: z.string().optional(),
    title: z.string(),
    summary: z.string(),
    description: z.string().optional(),
    featured: z.boolean().default(false),
    order: z.number().optional(),
    category: z.string(),
    stack: z.array(z.string()).default([]),
    tags: z.array(z.string()).default([]),
    links: z
      .object({
        github: z.string().optional(),
        demo: z.string().optional(),
        docs: z.string().optional(),
      })
      .default({}),
    screenshots: z
      .array(z.object({ src: z.string(), alt: z.string() }))
      .default([]),
    status: z
      .enum(['active', 'archived', 'prototype', 'school'])
      .optional(),
    startDate: z.string().optional(),
    updatedAt: z.string().optional(),
    draft: z.boolean().default(false),
  }),
});

const writeups = defineCollection({
  loader: glob({
    pattern: '**/*.{md,mdx}',
    base: './src/content/writeups',
  }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    event: z.string(),
    year: z.number(),
    category: z.enum(CATEGORIES),
    tags: z.array(z.string()).default([]),
    difficulty: z.enum(['easy', 'medium', 'hard', 'insane']).optional(),
    points: z.number().optional(),
    solves: z.number().optional(),
    date: z.string().optional(),
    sourceRepo: z.string().optional(),
    sourcePath: z.string().optional(),
    challengeUrl: z.string().optional(),
    draft: z.boolean().default(false),
    featured: z.boolean().default(false),
    flagsHidden: z.boolean().default(false),
  }),
});

export const collections = { projects, writeups };
