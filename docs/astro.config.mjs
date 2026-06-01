import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import sitemap from "@astrojs/sitemap";
import mermaid from "astro-mermaid";
import starlightPageActions from "starlight-page-actions";
import starlightLlmsTxt from "starlight-llms-txt";
import remarkGfm from "remark-gfm";

// https://astro.build/config
export default defineConfig({
  // Placeholder site/base — update to the real GitHub Pages URL on first deploy.
  site: "https://example.invalid/",
  base: "/agentic-security-lab",

  integrations: [
    // astro-mermaid MUST come before starlight in the integrations array.
    mermaid(),
    starlight({
      title: "agentic-security-lab",
      description:
        "Runtime, sandbox, ledger, and audit-log primitives for a code-analysis agent on Amazon Bedrock. Six asec-* Python packages plus 19 EARS invariants.",

      // Internal repo — edit link disabled.
      editLink: undefined,

      lastUpdated: true,

      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/lalsaado/agentic-security-lab",
        },
      ],

      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 4,
      },

      sidebar: [
        { label: "Home", slug: "index" },
        {
          label: "Concepts",
          items: [{ autogenerate: { directory: "concepts" } }],
        },
        {
          label: "Guides",
          items: [{ autogenerate: { directory: "guides" } }],
        },
        {
          label: "Packages",
          items: [{ autogenerate: { directory: "packages" } }],
        },
        {
          label: "ADRs",
          collapsed: true,
          items: [{ autogenerate: { directory: "adrs" } }],
        },
        {
          label: "Reference",
          collapsed: true,
          items: [{ autogenerate: { directory: "reference" } }],
        },
      ],

      plugins: [
        starlightPageActions({
          actions: {
            chatgpt: true,
            claude: true,
            markdown: true,
          },
        }),
        starlightLlmsTxt({
          projectName: "agentic-security-lab",
          description:
            "Six asec-* Python packages (sandbox, memory, skills, threat-model, confidence, core) implementing the runtime, ledger, and audit-log layers for a Claude Opus 4.8 code-analysis agent on Amazon Bedrock. Contract: 19 EARS invariants.",
          promote: ["index*", "concepts/*", "guides/*"],
          exclude: ["adrs/*"],
        }),
      ],
    }),
    sitemap(),
  ],

  markdown: {
    // remark-gfm explicit: Astro 6.4 + @astrojs/mdx 5 no longer auto-injects
    // GFM into the MDX processor, so tables in .mdx silently stop rendering
    // unless listed here. Restores GFM for both .md and .mdx.
    remarkPlugins: [remarkGfm],
  },
});
