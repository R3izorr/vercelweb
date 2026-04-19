export function formatDate(
  date: string | Date | null | undefined,
  opts: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  },
): string {
  if (!date) return '';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('en-US', opts);
}

export function formatMonthYear(date: string | Date | null | undefined): string {
  return formatDate(date, { year: 'numeric', month: 'short' });
}

export function truncate(s: string | null | undefined, len = 140): string {
  if (!s) return '';
  return s.length > len ? `${s.slice(0, len - 1).trimEnd()}…` : s;
}

const LANG_COLORS: Record<string, string> = {
  TypeScript: '#3178c6',
  JavaScript: '#f1e05a',
  Python: '#3572A5',
  Java: '#b07219',
  'C++': '#f34b7d',
  C: '#555555',
  HTML: '#e34c26',
  CSS: '#563d7c',
  Shell: '#89e051',
  Markdown: '#083fa1',
  Go: '#00ADD8',
  Rust: '#dea584',
};

export function langColor(lang?: string | null): string {
  if (!lang) return '#888';
  return LANG_COLORS[lang] ?? '#888';
}
