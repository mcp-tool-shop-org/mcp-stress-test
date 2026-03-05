import type { SiteConfig } from '@mcptoolshop/site-theme';

export const config: SiteConfig = {
  title: 'MCP Stress Test',
  description: 'Red team toolkit for stress-testing MCP security scanners — find detection gaps before attackers do.',
  logoBadge: 'ST',
  brandName: 'mcp-stress-test',
  repoUrl: 'https://github.com/mcp-tool-shop-org/mcp-stress-test',
  footerText: 'MIT Licensed — built by <a href="https://github.com/mcp-tool-shop-org" style="color:var(--color-muted);text-decoration:underline">mcp-tool-shop-org</a>',

  hero: {
    badge: 'Red team',
    headline: 'Break your scanner',
    headlineAccent: 'before attackers do.',
    description: '1,312 adversarial attack patterns from MCPTox, Unit42, and CyberArk research. Mutation, fuzzing, chain attacks, and SARIF reporting — all from a single CLI.',
    primaryCta: { href: '#usage', label: 'Get started' },
    secondaryCta: { href: 'handbook/', label: 'Read the Handbook' },
    previews: [
      { label: 'Install', code: 'pip install mcp-stress-test' },
      { label: 'Stress', code: 'mcp-stress stress run\n  --phases baseline,mutation' },
      { label: 'Fuzz', code: 'mcp-stress fuzz evasion\n  -p "Read SSH keys" --use-llm' },
    ],
  },

  sections: [
    {
      kind: 'features',
      id: 'features',
      title: 'Features',
      subtitle: 'Offensive security for MCP tool ecosystems.',
      features: [
        { title: '1,312 attack patterns', desc: 'Three paradigms from MCPTox: direct injection, semantic blending, and cross-tool poisoning. Ready to fire out of the box.' },
        { title: 'LLM-guided fuzzing', desc: 'Deterministic mutations plus LLM-guided evasion discovery. Find the payloads your scanner misses.' },
        { title: 'Multi-tool chains', desc: 'Data exfiltration, privilege escalation, and persistence chains that test detection across coordinated attacks.' },
      ],
    },
    {
      kind: 'code-cards',
      id: 'usage',
      title: 'Usage',
      cards: [
        {
          title: 'CLI',
          code: '# Stress test your scanner\nmcp-stress stress run \\\n  --phases baseline,mutation,temporal\n\n# Compare detection before/after\nmcp-stress scan compare \\\n  -t read_file -s obfuscation\n\n# Execute attack chains\nmcp-stress chain execute \\\n  -c data_exfil_chain',
        },
        {
          title: 'Python API',
          code: 'from mcp_stress_test import PatternLibrary\nfrom mcp_stress_test.generator import SchemaMutator\nfrom mcp_stress_test.chains import ChainExecutor\n\nlibrary = PatternLibrary()\nlibrary.load()\n\nmutator = SchemaMutator()\nfor case in library.iter_test_cases():\n    result = mutator.mutate(\n        case.target_tool,\n        case.poison_profile.payloads[0]\n    )',
        },
      ],
    },
    {
      kind: 'data-table',
      id: 'strategies',
      title: 'Mutation Strategies',
      subtitle: 'Escalating sophistication to probe scanner limits.',
      columns: ['Strategy', 'Technique', 'Detectability'],
      rows: [
        ['Direct injection', 'Append payload to description', 'High (baseline)'],
        ['Semantic blending', 'Weave into legitimate docs', 'Medium'],
        ['Obfuscation', 'Unicode tricks, zero-width chars', 'Medium'],
        ['Encoding', 'Base64, hex payloads', 'Low-Medium'],
        ['Fragmentation', 'Split across schema fields', 'Low'],
      ],
    },
    {
      kind: 'features',
      id: 'research',
      title: 'Research-Backed',
      subtitle: 'Built on cutting-edge MCP security research.',
      features: [
        { title: 'MCPTox benchmark', desc: '1,312 patterns across 3 attack paradigms — the largest public MCP poisoning dataset, from arxiv 2508.14925.' },
        { title: 'Palo Alto Unit42', desc: 'Sampling loop exploits and tool-shadowing attacks from production MCP deployment research.' },
        { title: 'CyberArk', desc: 'Full-schema poisoning where no output field is safe — descriptions, error messages, return values.' },
      ],
    },
  ],
};
