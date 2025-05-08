import type { SignatureDefinition } from '../signatures';

export const utilityLibrariesSignatures: SignatureDefinition[] = [
  {
    name: "jQuery",
    versions: {
      versionProperty: "$.fn.jquery",
      "jQuery 1.x": {
        weight: 0.9,
        patterns: [
          { type: "jsVersion", pattern: /^1\./, versionProperty: "$.fn.jquery", weight: 0.9 },
          { type: "script", pattern: /code\.jquery\.com\/jquery-1\./i, weight: 0.8 },
        ]
      },
      "jQuery 2.x": {
        weight: 0.9,
        patterns: [
          { type: "jsVersion", pattern: /^2\./, versionProperty: "$.fn.jquery", weight: 0.9 },
          { type: "script", pattern: /code\.jquery\.com\/jquery-2\./i, weight: 0.8 },
        ]
      },
      "jQuery 3.x": {
        weight: 0.9,
        patterns: [
          { type: "jsVersion", pattern: /^3\./, versionProperty: "$.fn.jquery", weight: 0.9 },
          { type: "script", pattern: /code\.jquery\.com\/jquery-3\./i, weight: 0.8 },
        ]
      },
      "jQuery Unspecified Version": {
        weight: 0.8,
        patterns: [
        ]
      },
      patterns: [ // These are general patterns for jQuery, not version specific patterns for "jQuery Unspecified Version"
        { type: "jsGlobal", pattern: "jQuery", weight: 0.9 },
        { type: "jsGlobal", pattern: "$", weight: 0.9 }, // Note: '$' can be ambiguous
        { type: "script", pattern: /jquery(?:-\d\.\d+\.\d+)?(?:dist\/)?(?:cdn\/)?(?:libs\/)?jquery(?:\.slim)?(?:\.min)?\.js/i, weight: 0.8 },
        { type: "html", pattern: /<script[^>]+jquery/i },
        { type: "html", pattern: /<script[^>]+jquery-migrate/i },
      ]
    },
    versionProperty: "$.fn.jquery", // This is redundant if versions object handles it but can be a fallback
  },
  {
    name: "Lodash",
    weight: 0.9,
    patterns: [
      { type: "jsGlobal", pattern: "_" }, // Note: '_' can be ambiguous
      { type: "script", pattern: /lodash(?:\.min)?\.js/i }
    ]
  }
];
