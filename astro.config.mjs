// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import tailwindcss from '@tailwindcss/vite';
import icon from 'astro-icon';
import rehypeAutolinkHeadings from 'rehype-autolink-headings';
import { rehypeHeadingIds } from '@astrojs/markdown-remark';

export default defineConfig({
  site: 'https://r3izorr.dev',
  output: 'static',
  trailingSlash: 'ignore',
  integrations: [
    icon({
      include: {
        lucide: ['*'],
        'simple-icons': ['*'],
      },
    }),
    mdx(),
    sitemap(),
  ],
  markdown: {
    syntaxHighlight: 'shiki',
    shikiConfig: {
      themes: {
        light: 'github-light',
        dark: 'github-dark-dimmed',
      },
      wrap: true,
    },
    rehypePlugins: [
      rehypeHeadingIds,
      [
        rehypeAutolinkHeadings,
        {
          behavior: 'append',
          properties: {
            class: 'autolink',
            ariaHidden: true,
            tabIndex: -1,
          },
          test: ['h2', 'h3', 'h4', 'h5'],
        },
      ],
    ],
  },
  vite: {
    plugins: [tailwindcss()],
  },
});
