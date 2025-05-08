import type { SignatureDefinition } from '../signatures';

export const hostingProvidersSignatures: SignatureDefinition[] = [
  {
    name: "Cloudways",
    weight: 0.8,
    patterns: [
      { type: "header", pattern: "server", value: /cloudways/i }, // Check server header
      { type: "networkRequest", pattern: /cloudwaysapps\.com/i }, // Domains used by Cloudways
      { type: "error", pattern: /cloudways/i } // Check error page content
    ]
  },
  {
    name: "Digital Ocean",
    weight: 0.7,
    patterns: [
      { type: "header", pattern: "server", value: /digitalocean/i },
      { type: "networkRequest", pattern: /digitalocean( droplets)?/i } // Check for related domains or terms
    ]
  }
  // Add others like AWS (more specific than just ELB/CF), Google Cloud, Azure, Netlify, Vercel, etc.
];
