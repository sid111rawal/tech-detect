import type { SignatureDefinition } from '../signatures';

export const serverPlatformsSignatures: SignatureDefinition[] = [
  {
    name: "Apache",
    weight: 0.9,
    patterns: [
      { type: "header", pattern: "server", value: /apache/i, weight: 0.9 },
      { type: "header", pattern: "x-powered-by", value: /apache/i, weight: 0.7 }, // Less common for Apache itself
      { type: "html", pattern: /Apache Web Server/i, weight: 0.6 }, // Found in default error pages
      { type: "error", pattern: /Apache/i, weight: 0.7 } // Check error page content if available
    ]
  },
  {
    name: "Nginx",
    weight: 0.9,
    patterns: [
      { type: "header", pattern: "server", value: /nginx/i }
    ]
  },
  {
    name: "Express.js",
    weight: 0.8,
    patterns: [
      { type: "header", pattern: "x-powered-by", value: /express/i }
    ]
  }
  // LiteSpeed, IIS, etc. can be added here
];
