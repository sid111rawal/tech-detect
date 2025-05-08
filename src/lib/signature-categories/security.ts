import type { SignatureDefinition } from '../signatures';

export const securitySignatures: SignatureDefinition[] = [
  {
    name: "HSTS",
    weight: 0.9,
    patterns: [
      { type: "header", pattern: "strict-transport-security" }
    ]
  },
  {
    name: "Content Security Policy",
    weight: 0.9,
    patterns: [
      { type: "header", pattern: "content-security-policy" },
      { type: "meta", pattern: { name: "content-security-policy" } } // Meta tag based CSP
    ]
  }
];
