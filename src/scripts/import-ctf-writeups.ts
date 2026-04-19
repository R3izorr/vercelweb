#!/usr/bin/env tsx
/**
 * Import Markdown writeups from R3izorr/CTF_writeup into Astro content routes.
 *
 * The source repo is organized as CTF/event folders with arbitrary deeper
 * challenge folders. Astro routes need a stable shape:
 *
 *   src/content/writeups/{year}/{event}/{category}/{slug}.md
 *
 * This script recursively finds README.md / READEME.md files, infers metadata,
 * and copies only Markdown. Challenge binaries, Docker files, solve scripts,
 * libc/ld files, and flag files stay in the source repo and are linked by
 * sourcePath.
 */

import {
  mkdir,
  readdir,
  readFile,
  stat,
  writeFile,
} from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

const SOURCE_REPO = 'R3izorr/CTF_writeup';
const DEFAULT_SOURCE_DIR = '/tmp/r3izorr-CTF_writeup';
const DEFAULT_OUT_DIR = resolve(process.cwd(), 'src/content/writeups');
const DEFAULT_YEAR = 2025;

const sourceDir = resolve(process.argv[2] ?? DEFAULT_SOURCE_DIR);
const outDir = resolve(process.argv[3] ?? DEFAULT_OUT_DIR);

const CATEGORY_PATTERNS: Array<{
  category: Category;
  matches: string[];
}> = [
  { category: 'pwn', matches: ['pwn', 'bin', 'binex', 'binary', 'exploit'] },
  { category: 'rev', matches: ['rev', 'reverse', 'reversing'] },
  { category: 'web', matches: ['web'] },
  { category: 'crypto', matches: ['crypto', 'cryptography', 'cry'] },
  { category: 'forensics', matches: ['forensic', 'forensics'] },
  { category: 'osint', matches: ['osint'] },
  { category: 'misc', matches: ['misc'] },
];

type Category =
  | 'pwn'
  | 'rev'
  | 'web'
  | 'crypto'
  | 'forensics'
  | 'osint'
  | 'misc';

interface SourceWriteup {
  filePath: string;
  relFile: string;
  sourcePath: string;
  body: string;
  title: string;
  description?: string;
  year: number;
  event: string;
  eventSlug: string;
  category: Category;
  slug: string;
  tags: string[];
}

function slugify(input: string): string {
  return input
    .normalize('NFKD')
    .replace(/[^\w\s-]/g, '')
    .toLowerCase()
    .trim()
    .replace(/[_\s]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function titleCaseToken(input: string): string {
  const known = new Map<string, string>([
    ['ctf', 'CTF'],
    ['osint', 'OSINT'],
    ['qnodeqsec', 'QnQSec'],
    ['qnqsec', 'QnQSec'],
    ['v1tctf', 'V1T CTF'],
    ['tkbctf', 'TKB CTF'],
    ['h7ctf', 'H7 CTF'],
    ['k17ctf', 'K17 CTF'],
    ['bitsctf', 'BITS CTF'],
    ['osuctf', 'OSU CTF'],
    ['xmas', 'XMAS'],
  ]);

  const compact = input.toLowerCase().replace(/[^a-z0-9]/g, '');
  const knownValue = known.get(compact);
  if (knownValue) return knownValue;

  return input
    .replace(/[_-]+/g, ' ')
    .split(' ')
    .filter(Boolean)
    .map((part) => {
      if (/^ctf$/i.test(part)) return 'CTF';
      return `${part.charAt(0).toUpperCase()}${part.slice(1)}`;
    })
    .join(' ');
}

function cleanTitle(input: string): string {
  return input
    .replace(/^#+\s*/, '')
    .replace(/[*_`"“”]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function yamlString(value: string): string {
  return JSON.stringify(value);
}

function firstHeading(markdown: string): string | undefined {
  const line = markdown
    .split('\n')
    .find((candidate) => /^#{1,3}\s+\S/.test(candidate));
  return line ? cleanTitle(line) : undefined;
}

function firstParagraph(markdown: string): string | undefined {
  const paragraph = markdown
    .replace(/^---[\s\S]*?---\s*/, '')
    .split(/\n{2,}/)
    .map((part) => part.trim())
    .find(
      (part) =>
        part.length > 0 &&
        !part.startsWith('#') &&
        !part.startsWith('```') &&
        !part.startsWith('>') &&
        !part.startsWith('!['),
    );

  if (!paragraph) return undefined;
  return paragraph
    .replace(/\n/g, ' ')
    .replace(/\s+/g, ' ')
    .slice(0, 180)
    .trim();
}

function stripFrontmatter(markdown: string): string {
  return markdown.replace(/^---[\s\S]*?---\s*/, '').trimStart();
}

function inferYear(parts: string[]): number {
  const fromPath = parts
    .join(' ')
    .match(/(?:20\d{2}|19\d{2})/)?.[0];
  if (fromPath) return Number(fromPath);

  return DEFAULT_YEAR;
}

function findCategory(parts: string[], markdown: string): Category {
  for (const part of parts) {
    const normalized = part.toLowerCase().replace(/[^a-z0-9]/g, '');
    for (const { category, matches } of CATEGORY_PATTERNS) {
      if (matches.some((match) => normalized.includes(match))) {
        return category;
      }
    }
  }

  const heading = firstHeading(markdown)?.toLowerCase() ?? '';
  if (/rev\s*\/\s*crypto|crypto\s*\/\s*rev|cryptography|crypto/.test(heading)) {
    return 'crypto';
  }
  if (/\brev\b|reverse|reversing/.test(heading)) return 'rev';
  if (/\bpwn\b|binary exploitation|buffer overflow|format string/.test(heading)) {
    return 'pwn';
  }
  if (/\bweb\b|xss|flask|http/.test(heading)) return 'web';
  if (/\bosint\b/.test(heading)) return 'osint';

  const haystack = markdown.toLowerCase();
  if (/format string|buffer overflow|ret2|rop|heap|tcache|libc|fsop|srop/.test(haystack)) {
    return 'pwn';
  }
  if (/reverse|ghidra|ida|jadx|apk|decompil|shellcode|elf/.test(haystack)) {
    return 'rev';
  }
  if (/flask|xss|csrf|ssti|http|cookie|jwt/.test(haystack)) {
    return 'web';
  }
  if (/aes|rsa|xor|cipher|decrypt|encrypt|gcm/.test(haystack)) {
    return 'crypto';
  }
  if (/pcap|wireshark|memory dump|forensic/.test(haystack)) {
    return 'forensics';
  }
  if (/osint|image|minecraft/.test(haystack)) {
    return 'osint';
  }

  return 'misc';
}

function inferTags(markdown: string, category: Category): string[] {
  const tags = new Set<string>([category]);
  const checks: Array<[string, RegExp]> = [
    ['format-string', /format string|%n|\$hn/i],
    ['rop', /\brop\b|ret2/i],
    ['heap', /heap|tcache|unsorted bin|safe-linking/i],
    ['srop', /\bsrop\b|sigreturn/i],
    ['fsop', /\bfsop\b|_IO_/i],
    ['xss', /\bxss\b|cross-site/i],
    ['android', /android|apk|jadx/i],
    ['crypto', /aes|rsa|xor|cipher|decrypt|encrypt|gcm/i],
    ['ghidra', /ghidra/i],
    ['pwntools', /pwntools|from pwn import/i],
    ['docker', /docker|compose\.yml|dockerfile/i],
  ];

  for (const [tag, pattern] of checks) {
    if (pattern.test(markdown)) tags.add(tag);
  }

  return [...tags].slice(0, 8);
}

function inferSlug(parts: string[], title: string): string {
  const ignored = new Set([
    'readme',
    'reademe',
    'pub',
    'dist',
    'new-folder',
    'new',
    'folder',
    'pwn',
    'rev',
    'reverse',
    'web',
    'crypto',
    'forensics',
    'osint',
    'misc',
    'exploit',
  ]);

  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const candidate = slugify(parts[index] ?? '');
    if (candidate && !ignored.has(candidate)) return candidate;
  }

  return slugify(title) || 'writeup';
}

function normalizeEventName(rawEvent: string): string {
  return rawEvent
    .replace(/[_-]+/g, ' ')
    .replace(/\b20\d{2}\b/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .split(' ')
    .map(titleCaseToken)
    .join(' ');
}

async function walk(dir: string): Promise<string[]> {
  const files: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.name === '.git') continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(fullPath)));
      continue;
    }

    if (/^(readme|reademe)\.md$/i.test(entry.name)) {
      files.push(fullPath);
    }
  }

  return files;
}

async function existingSourcePaths(): Promise<Set<string>> {
  if (!existsSync(outDir)) return new Set();

  const paths = new Set<string>();
  async function scan(dir: string) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        await scan(fullPath);
        continue;
      }
      if (!/\.mdx?$/i.test(entry.name)) continue;

      const content = await readFile(fullPath, 'utf8');
      const match = content.match(/^sourcePath:\s*["']?(.+?)["']?\s*$/m);
      if (match?.[1]) paths.add(match[1]);
    }
  }

  await scan(outDir);
  return paths;
}

function toWriteup(filePath: string, body: string): SourceWriteup | null {
  const relFile = relative(sourceDir, filePath);
  if (!relFile || relFile === 'README.md') return null;

  const dirRel = dirname(relFile);
  if (dirRel === '.') return null;

  const parts = dirRel.split(sep);
  const title = firstHeading(body) ?? titleCaseToken(parts.at(-1) ?? 'Writeup');
  const eventRaw = parts[0] ?? 'CTF';
  const event = normalizeEventName(eventRaw);
  const eventSlug =
    slugify(eventRaw.replace(/(^|[_\-\s])(?:20\d{2}|19\d{2})(?=$|[_\-\s])/g, '$1')) ||
    'ctf';
  const year = inferYear(parts);
  const category = findCategory(parts.slice(1), body);
  const slug = inferSlug(parts.slice(1), title);
  const tags = inferTags(body, category);

  return {
    filePath,
    relFile,
    sourcePath: dirRel.split(sep).join('/'),
    body,
    title,
    description: firstParagraph(body),
    year,
    event,
    eventSlug,
    category,
    slug,
    tags,
  };
}

async function uniqueTargetPath(writeup: SourceWriteup): Promise<string> {
  const baseDir = join(
    outDir,
    String(writeup.year),
    writeup.eventSlug,
    writeup.category,
  );
  let candidate = join(baseDir, `${writeup.slug}.md`);
  let suffix = 2;

  while (existsSync(candidate)) {
    const content = await readFile(candidate, 'utf8');
    if (content.includes(`sourcePath: ${yamlString(writeup.sourcePath)}`)) {
      return candidate;
    }
    candidate = join(baseDir, `${writeup.slug}-${suffix}.md`);
    suffix += 1;
  }

  return candidate;
}

function renderWriteup(writeup: SourceWriteup): string {
  const body = stripFrontmatter(writeup.body);
  const sourceUrl = `https://github.com/${SOURCE_REPO}/tree/main/${encodeURI(writeup.sourcePath)}`;

  return `---
title: ${yamlString(writeup.title)}
description: ${yamlString(writeup.description ?? `${writeup.title} writeup.`)}
event: ${yamlString(writeup.event)}
year: ${writeup.year}
category: ${writeup.category}
tags: ${JSON.stringify(writeup.tags)}
sourceRepo: ${yamlString(SOURCE_REPO)}
sourcePath: ${yamlString(writeup.sourcePath)}
featured: false
flagsHidden: false
---

> Imported from [${writeup.sourcePath}](${sourceUrl}).

${body}
`;
}

async function main() {
  const sourceStats = await stat(sourceDir).catch(() => null);
  if (!sourceStats?.isDirectory()) {
    throw new Error(
      `Source CTF repo not found at ${sourceDir}. Clone it first: git clone https://github.com/${SOURCE_REPO} ${sourceDir}`,
    );
  }

  const existing = await existingSourcePaths();
  const readmes = await walk(sourceDir);
  let imported = 0;
  let skipped = 0;

  for (const filePath of readmes) {
    const body = await readFile(filePath, 'utf8');
    const writeup = toWriteup(filePath, body);
    if (!writeup) {
      skipped += 1;
      continue;
    }

    if (existing.has(writeup.sourcePath)) {
      skipped += 1;
      continue;
    }

    const targetPath = await uniqueTargetPath(writeup);
    await mkdir(dirname(targetPath), { recursive: true });
    await writeFile(targetPath, renderWriteup(writeup));
    existing.add(writeup.sourcePath);
    imported += 1;

    console.log(
      `imported ${writeup.sourcePath} -> ${relative(process.cwd(), targetPath)}`,
    );
  }

  console.log(
    `Done. ${imported} imported, ${skipped} skipped, ${readmes.length} README files scanned.`,
  );
}

main().catch((err) => {
  console.error('[import-ctf-writeups] failed:', err);
  process.exit(1);
});
