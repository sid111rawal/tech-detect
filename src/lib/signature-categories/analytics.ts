import type { SignatureDefinition } from '../signatures';

export const analyticsSignatures: SignatureDefinition[] = [
  {
    name: "Google Analytics",
    versions: {
      "Universal Analytics": {
        weight: 0.9,
        patterns: [ // Universal Analytics patterns
          { type: "script", pattern: /www\.google-analytics\.com\/analytics\.js/i, weight: 0.9 }, // Main UA script
          { type: "script", pattern: /www\.googletagmanager\.com\/gtag\/js/i, weight: 0.8 }, // Gtag script (can be used by both UA and GA4)
          { type: "cookie", pattern: /^_gid/, weight: 0.7 }, // Secondary GA cookie
          { type: "cookie", pattern: /^_gat/, weight: 0.6 }, // Throttle cookie
          { type: "jsGlobal", pattern: "ga", weight: 0.8 }, // Global function
          { type: "jsGlobal", pattern: "gtag" },
          { type: "jsGlobal", pattern: "dataLayer" },
          // Obfuscated patterns
          { type: "html", pattern: /function\s*\(\s*[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\s*\)\s*\{\s*[a-z]\s*\.\s*[a-z]\s*=\s*[a-z]\s*\.\s*[a-z]\s*\|\|\s*\[\]/i, weight: 0.7 },
          { type: "networkRequest", pattern: /collect\?v=1&_v=j\d+&/i }
        ]
      },
      "GA4": {
        weight: 0.95,
        patterns: [ // GA4 patterns
          { type: "script", pattern: /www\.googletagmanager\.com\/gtag\/js\?id=G-/i, weight: 0.95 }, // GA4 script
          { type: "jsGlobal", pattern: "gtag" },
          { type: "networkRequest", pattern: /\/g\/collect\?v=2/i }
        ]
      }
    }
  },
  {
    name: "Mixpanel",
    weight: 0.9,
    patterns: [
      { type: "script", pattern: /cdn\.mxpnl\.com\/libs\/mixpanel/i },
      { type: "script", pattern: /cdn\.mixpanel\.com\/mixpanel/i },
      { type: "cookie", pattern: /^mp_/ },
      { type: "jsGlobal", pattern: "mixpanel" },
      // Obfuscated patterns
      { type: "networkRequest", pattern: /api\/2\.0\/track/i },
      { type: "html", pattern: /function\s*\(\s*[a-z]\s*\)\s*\{\s*return\s*[a-z]\s*\.\s*[a-z]+\s*\(\s*"mixpanel"\s*\)/i, weight: 0.7 }
    ]
  },
  {
    name: "Segment",
    weight: 0.9,
    patterns: [
      { type: "script", pattern: /cdn\.segment\.com\/analytics\.js/i },
      { type: "cookie", pattern: /^ajs_/ },
      { type: "jsGlobal", pattern: "analytics" },
      { type: "networkRequest", pattern: /api\.segment\.io\/v1/i },
      // Obfuscated patterns
      { type: "html", pattern: /window\.analytics\s*=\s*window\.analytics\s*\|\|\s*\[\]/i, weight: 0.8 }
    ]
  },
  {
    name: "Zipkin",
    weight: 0.9,
    patterns: [
      { type: "script", pattern: /zipkin/i },
      { type: "header", pattern: "x-b3-traceid" },
      { type: "header", pattern: "x-b3-spanid" },
      { type: "header", pattern: "x-b3-sampled" },
      { type: "networkRequest", pattern: /api\/v2\/spans/i },
      { type: "html", pattern: /zipkin/i }
    ]
  }
];
