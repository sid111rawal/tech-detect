import type { SignatureDefinition } from '../signatures';

export const hostedCmsSignatures: SignatureDefinition[] = [
  {
    name: "Ghost",
    weight: 0.9,
    patterns: [
      { type: "header", pattern: "x-ghost-cache-status" },
      { type: "meta", pattern: { name: "generator", content: /Ghost/i }, weight: 0.9 },
      { type: "html", pattern: /ghost/i }, // General keyword check
      { type: "script", pattern: /ghost/i } // General keyword check in scripts
    ]
  }
  // Add Shopify here if it's considered primarily hosted CMS
  // {
  //   name: "Shopify",
  //   weight: 0.95,
  //   patterns: [
  //     { type: "script", pattern: /cdn\.shopify\.com/i, weight: 0.9 },
  //     { type: "html", pattern: /Shopify\.theme/i, weight: 0.8 },
  //     { type: "cookie", pattern: /^_shopify_/, weight: 0.7 },
  //     { type: "jsGlobal", pattern: "Shopify", weight: 0.9 },
  //     { type: "networkRequest", pattern: /shopify\.com/i, weight: 0.7}
  //   ]
  // }
];
