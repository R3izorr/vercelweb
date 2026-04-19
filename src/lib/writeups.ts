import { getCollection, type CollectionEntry } from 'astro:content';

export type WriteupEntry = CollectionEntry<'writeups'>;

export const CATEGORY_LABELS: Record<string, string> = {
  pwn: 'Binary Exploitation',
  rev: 'Reverse Engineering',
  web: 'Web',
  crypto: 'Cryptography',
  forensics: 'Forensics',
  osint: 'OSINT',
  misc: 'Misc',
};

export const CATEGORY_ICONS: Record<string, string> = {
  pwn: 'lucide:skull',
  rev: 'lucide:eye',
  web: 'lucide:globe',
  crypto: 'lucide:lock',
  forensics: 'lucide:search',
  osint: 'lucide:telescope',
  misc: 'lucide:sparkles',
};

export const CATEGORY_TONE: Record<
  string,
  'default' | 'accent' | 'sky' | 'amber' | 'rose' | 'violet' | 'orange'
> = {
  pwn: 'rose',
  rev: 'violet',
  web: 'sky',
  crypto: 'amber',
  forensics: 'accent',
  osint: 'orange',
  misc: 'default',
};

export function writeupHref(entry: WriteupEntry): string {
  const parts = entry.id.split('/');
  if (parts.length >= 4) {
    return `/writeups/${parts.join('/')}`;
  }
  const { year, event, category } = entry.data;
  return `/writeups/${year}/${slugify(event)}/${category}/${parts[parts.length - 1]}`;
}

export function writeupSlugParts(entry: WriteupEntry): {
  year: string;
  event: string;
  category: string;
  slug: string;
} {
  const parts = entry.id.split('/');
  return {
    year: parts[0],
    event: parts[1],
    category: parts[2],
    slug: parts[3],
  };
}

export function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

export async function getWriteups(
  opts: { includeDrafts?: boolean } = {},
): Promise<WriteupEntry[]> {
  const { includeDrafts = false } = opts;
  const entries = await getCollection('writeups', (e) =>
    includeDrafts ? true : !e.data.draft,
  );
  return entries.sort((a, b) => {
    const ad = a.data.date ?? `${a.data.year}-12-31`;
    const bd = b.data.date ?? `${b.data.year}-12-31`;
    return bd.localeCompare(ad);
  });
}

export async function getYears(): Promise<number[]> {
  const entries = await getWriteups();
  const years = new Set<number>();
  entries.forEach((e) => years.add(e.data.year));
  return [...years].sort((a, b) => b - a);
}

export async function getEvents(
  year?: number,
): Promise<{ event: string; slug: string; year: number; count: number }[]> {
  const entries = await getWriteups();
  const map = new Map<string, { event: string; year: number; count: number }>();
  for (const e of entries) {
    if (year !== undefined && e.data.year !== year) continue;
    const key = `${e.data.year}::${e.data.event}`;
    const cur = map.get(key);
    if (cur) {
      cur.count += 1;
    } else {
      map.set(key, {
        event: e.data.event,
        year: e.data.year,
        count: 1,
      });
    }
  }
  return [...map.values()]
    .map((v) => ({ ...v, slug: slugify(v.event) }))
    .sort((a, b) => (a.year !== b.year ? b.year - a.year : a.event.localeCompare(b.event)));
}

export async function getCategories(): Promise<
  { category: string; label: string; count: number }[]
> {
  const entries = await getWriteups();
  const map = new Map<string, number>();
  entries.forEach((e) => {
    map.set(e.data.category, (map.get(e.data.category) ?? 0) + 1);
  });
  return [...map.entries()]
    .map(([category, count]) => ({
      category,
      label: CATEGORY_LABELS[category] ?? category,
      count,
    }))
    .sort((a, b) => b.count - a.count);
}

export async function getTags(): Promise<{ tag: string; count: number }[]> {
  const entries = await getWriteups();
  const map = new Map<string, number>();
  entries.forEach((e) => {
    (e.data.tags ?? []).forEach((t: string) => {
      map.set(t, (map.get(t) ?? 0) + 1);
    });
  });
  return [...map.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count);
}
