import type { SignatureDefinition } from '../signatures'; // Adjust path as needed

// This structure assumes that each category file exports an array of SignatureDefinition
export interface SignaturesByCategory {
  analytics: SignatureDefinition[];
  utility_libraries: SignatureDefinition[];
  payment_processors: SignatureDefinition[];
  security: SignatureDefinition[];
  miscellaneous: SignatureDefinition[];
  cookie_compliance: SignatureDefinition[];
  self_hosted_cms: SignatureDefinition[];
  hosted_cms: SignatureDefinition[];
  css_frameworks: SignatureDefinition[];
  server_platforms: SignatureDefinition[];
  hosting_providers: SignatureDefinition[];
  reverse_proxies: SignatureDefinition[];
  programming_languages: SignatureDefinition[];
  databases: SignatureDefinition[];
  marketing_automation: SignatureDefinition[];
  // Add other categories here as they are created
  // e.g. javascript_frameworks: SignatureDefinition[];
  // video_players: SignatureDefinition[];
  // etc.
}

// Example of how you might combine them if you choose to do so in an index.
// However, it's often cleaner to import them directly where needed in signatures.ts

// export { analyticsSignatures } from './analytics';
// export { utilityLibrariesSignatures } from './utility_libraries';
// ... and so on for all categories
