import type { SignatureDefinition } from '../signatures';

export const cssFrameworksSignatures: SignatureDefinition[] = [
  {
    name: "Bootstrap",
    // category: "css_frameworks", // Category handled by file name
    versions: {
      "Bootstrap 3.x": {
        weight: 0.9,
        patterns: [
          { type: "script", pattern: /bootstrap(?:cdn)?\.com\/bootstrap\/3\./i, weight: 0.9 },
          { type: "css", pattern: /bootstrap(?:cdn)?\.com\/bootstrap\/3\./i, weight: 0.9 }
        ]
      },
      "Bootstrap 4.x": {
        weight: 0.9,
        patterns: [
          { type: "script", pattern: /bootstrap(?:cdn)?\.com\/bootstrap\/4\./i, weight: 0.9 },
          { type: "css", pattern: /bootstrap\/4\.[^\/]*\/css\/bootstrap(?:\.min)?\.css/i, weight: 0.9 }, // More specific CSS path
          { type: "css", pattern: /bootstrap(?:cdn)?\.com\/bootstrap\/4\./i, weight: 0.9 }
        ]
      },
      "Bootstrap 5.x": {
        weight: 0.9,
        patterns: [
          { type: "script", pattern: /bootstrap(?:cdn)?\.com\/bootstrap\/5\./i, weight: 0.9 },
          { type: "css", pattern: /bootstrap\/5\.[^\/]*\/css\/bootstrap(?:\.min)?\.css/i, weight: 0.9 },
          { type: "css", pattern: /bootstrap(?:cdn)?\.com\/bootstrap\/5\./i, weight: 0.9 }
        ]
      },
      patterns: [ // General Bootstrap patterns
        { type: "script", pattern: /bootstrap(?:\.bundle)?(?:\.min)?\.js/i, weight: 0.8 },
        { type: "css", pattern: /bootstrap(?:\.min)?\.css/i, weight: 0.8 },
        { type: "html", pattern: /class="[^"]*\bnavbar\b/i, weight: 0.7 }, // Use word boundary
        { type: "html", pattern: /class="[^"]*\bcontainer(?:-fluid)?\b/i, weight: 0.7 },
        { type: "html", pattern: /class="[^"]*\brow\b/i },
        { type: "html", pattern: /class="[^"]*\bcol-/i },
        { type: "html", pattern: /class="[^"]*\bbtn\b/i }
      ]
    }
  },
  {
    name: "Tailwind CSS",
    // category: "css_frameworks",
    weight: 0.9,
    patterns: [
      { type: "css", pattern: /tailwind(?:\.min)?\.css/i }, // Check for Tailwind CSS file
      { type: "html", pattern: /class="[^"]*\b(?:text-\w+-\d+|bg-\w+-\d+|p-\d+|m-\d+|flex|grid|items-center|justify-between)\b/i, weight: 0.6 } // Common Tailwind utility classes
    ]
  }
];
