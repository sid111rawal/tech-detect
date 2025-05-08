import type { SignatureDefinition } from '../signatures';

export const selfHostedCmsSignatures: SignatureDefinition[] = [
  {
    name: "WordPress",
    versions: {
      "Wordpress < 4.0": { // Example version specific definition
        patterns: [
          { type: "meta", pattern: { name: "generator", content: /WordPress ([0-3]\.\d+(\.\d+)?)/i }, weight: 0.9 }
        ]
      },
      "Wordpress >= 4.0": {
        weight: 0.9,
        patterns: [
          { type: "meta", pattern: { name: "generator", content: /WordPress ([4-9]\.\d+(\.\d+)?)/i }, weight: 0.9 }
        ]
      },
      "Wordpress >= 6.0": {
        weight: 0.9,
        patterns: [
          { type: "meta", pattern: { name: "generator", content: /WordPress ([6-9]\.\d+(\.\d+)?)/i }, weight: 0.9 }
        ]
      }
    },
    patterns: [ // General WordPress patterns
      { type: "meta", pattern: { name: "generator", content: /WordPress/i }, weight: 0.9 }, // More generic generator check
      { type: "script", pattern: /wp-content/, weight: 0.8 },
      { type: "script", pattern: /wp-includes/, weight: 0.8 },
      { type: "cookie", pattern: /wordpress_/, weight: 0.7 },
      { type: "cookie", pattern: /wp-settings-\d/, weight: 0.7 },
      { type: "cookie", pattern: /wp-settings-/i, weight: 0.7 }, // Case-insensitive
      { type: "networkRequest", pattern: /wp-json/i },
      { type: "jsGlobal", pattern: "wp" },
      { type: "html", pattern: /class="[^"]*wp-/i, weight: 0.6 }, // WP class prefix
      { type: "filePath", pattern: /\/wp-admin\//i, weight: 0.5 }, // Presence of /wp-admin/ in URL paths
      { type: "robots", pattern: /Disallow:\s*\/wp-admin\//i, weight: 0.5} // robots.txt disallowing /wp-admin/
    ]
  },
  {
    name: "Squarespace",
    // category: "hosted_cms", // Category should be handled by file name
    weight: 0.9,
    patterns: [
      { type: "script", pattern: /squarespace-assets\.com/i, weight: 0.8 },
      { type: "html", pattern: /squarespace-cdn/i, weight: 0.8 },
      { type: "html", pattern: /class="sqs-/i, weight: 0.7 },
      { type: "networkRequest", pattern: /squarespace\.com/i, weight: 0.7 },
      { type: "meta", pattern: { name: "generator", content: /Squarespace/i }, weight: 0.9 }
    ]
  },
  {
    name: "Wix",
    weight: 0.9,
    patterns: [
      { type: "html", pattern: /wix\.com/i, weight: 0.9 },
      { type: "html", pattern: /static\.parastorage\.com/i, weight: 0.8 },
      { type: "script", pattern: /wixstatic\.com/i, weight: 0.8 },
      { type: "script", pattern: /wix\.com/i, weight: 0.8 },
      { type: "networkRequest", pattern: /wix\.com/i, weight: 0.7 },
      { type: "cookie", pattern: /WIX_LOCALE/i },
      { type: "cookie", pattern: /SESS/i } // Can be generic, ensure higher confidence patterns for Wix exist
    ]
  },
  {
    name: "Drupal",
    weight: 0.9,
    patterns: [
      { type: "script", pattern: /drupal\.js/i },
      { type: "html", pattern: /drupal-/i },
      { type: "html", pattern: /data-drupal/i },
      { type: "jsGlobal", pattern: /Drupal/i }, // Case-insensitive global
      { type: "meta", pattern: { name: "generator", content: /Drupal/i } },
      { type: "cookie", pattern: /^SESS[a-f0-9]{32}$/i } // Drupal session cookie pattern
    ]
  },
  {
    name: "Joomla",
    // category: "self_hosted_cms",
    weight: 0.8,
    patterns: [
      { type: "html", pattern: /joomla/i, weight: 0.8 },
      { type: "meta", pattern: { name: "generator", content: /Joomla!/i }, weight: 0.9 },
      { type: "script", pattern: /joomla-core/i, weight: 0.7 },
      { type: "networkRequest", pattern: /joomla/i, weight: 0.7 },
      { type: "cookie", pattern: /[a-f0-9]{32}/i } // Joomla session cookie (often just a hash)
    ]
  }
];
