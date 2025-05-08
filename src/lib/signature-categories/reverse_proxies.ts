import type { SignatureDefinition } from '../signatures';

export const reverseProxiesSignatures: SignatureDefinition[] = [
  {
    name: "AWS Elastic Load Balancer", // More specific than just "AWS"
    weight: 0.8,
    patterns: [
      { type: "header", pattern: "server", value: /awselb\/\d\.\d/i },
      { type: "header", pattern: "x-amz-id-2" }, // S3 related, but often seen with ELB
      { type: "cookie", pattern: /^awselb$/i }, // ELB session cookie
    ]
  },
  {
    name: "AWS CloudFront",
    weight: 0.85,
    patterns: [
        { type: "header", pattern: "x-amz-cf-id" },
        { type: "header", pattern: "x-amz-cf-pop" },
        { type: "header", pattern: "via", value: /cloudfront/i },
        { type: "networkRequest", pattern: /\.cloudfront\.net/i }
    ]
  },
  {
    name: "Google Cloud Load Balancer", // More specific
    weight: 0.8,
    patterns: [
      { type: "header", pattern: "server", value: /Google Frontend/i, weight: 0.9 },
      { type: "header", pattern: "via", value: /google/i}, // Can be generic, use with other signals
      { type: "networkRequest", pattern: /googleapis\.com/i } // General Google API, less specific to LB
    ]
  },
  {
    name: "Cloudflare",
    weight: 0.95,
    patterns: [
      { type: "header", pattern: "cf-ray", weight: 0.9 },
      { type: "header", pattern: "cf-cache-status", weight: 0.8 },
      { type: "header", pattern: "server", value: /cloudflare/i, weight: 0.8 },
      { type: "cookie", pattern: /^__cfduid$/i, weight: 0.7 }, // Deprecated but might still be seen
      { type: "cookie", pattern: /^__cf_bm$/i, weight: 0.7 }, // Bot Management cookie
      { type: "networkRequest", pattern: /cdn\.jsdelivr\.net\/gh\//i, weight: 0.4, implies: ["jsDelivr"]}, // jsDelivr often behind CF
      { type: "jsGlobal", pattern: "Cloudflare" },
      { type: "filePath", pattern: /\/cdn-cgi\//i, weight: 0.6} // Cloudflare specific paths
    ]
  },
  {
    name: "Envoy",
    // category: "reverse_proxies", // Handled by file name
    weight: 0.9,
    patterns: [
      { type: "header", pattern: "server", value: /envoy/i },
      { type: "header", pattern: "x-envoy-upstream-service-time" }
    ]
  }
];
