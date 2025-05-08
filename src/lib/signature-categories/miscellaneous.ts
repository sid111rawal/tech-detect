import type { SignatureDefinition } from '../signatures';

export const miscellaneousSignatures: SignatureDefinition[] = [
  {
    name: "Open Graph",
    weight: 0.9,
    patterns: [
      { type: "meta", pattern: { name: "og:title" } }, // Check specific OG meta tags by name
      { type: "meta", pattern: { name: "og:type" } },
      { type: "meta", pattern: { name: "og:image" } },
      { type: "meta", pattern: { name: "og:url" } },
      { type: "html", pattern: /property=["']og:/i } // General check for OG properties in HTML
    ]
  }
];
