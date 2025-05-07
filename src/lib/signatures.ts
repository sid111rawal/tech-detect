/**
 * TechDetective Pro - Technology Signatures
 *
 * This file contains the signature database for detecting web technologies.
 * Enhanced with patterns for obfuscated/minified code detection and Wappalyzer-like features.
 */

import type { PageContentResult } from '@/services/page-retriever'; // Assuming this path
import { retrieveRobotsTxt } from '@/services/page-retriever';


// --- Type Definitions ---
interface PatternDefinition {
  type: 'html' | 'script' | 'css' | 'header' | 'meta' | 'cookie' | 'jsGlobal' | 'networkRequest' | 'jsVersion' | 'htmlComment' | 'error' | 'url' | 'robots' | 'dom';
  pattern: RegExp; // The main regex pattern
  value?: RegExp; // For headers, to match against the header's value
  name?: string; // For meta tags (name attribute) or cookie name
  content?: RegExp; // For meta tags (content attribute regex)
  versionProperty?: string; // For jsVersion, the global property path (e.g., "$.fn.jquery")
  versionCaptureGroup?: number; // Index of the regex capture group for version (1-based)
  weight?: number; // Confidence weight for this specific pattern (0.0 to 1.0)
  attributes?: Record<string, RegExp>; // For 'dom' type, to match attributes
  text?: RegExp; // For 'dom' type, to match text content
}

interface VersionSignature {
  weight?: number; // Overall weight/base confidence for this version if its patterns match
  patterns: PatternDefinition[];
}

interface SignatureDefinition {
  name: string;
  website?: string;
  icon?: string;
  cpe?: string; // Common Platform Enumeration
  saas?: boolean;
  oss?: boolean;
  pricing?: string[];
  weight?: number; // Default/base confidence if no specific version/pattern weight overrides
  versions?: Record<string, VersionSignature>; // Key is version name (e.g., "6.x", "Universal Analytics")
  patterns?: PatternDefinition[]; // General patterns if no specific versions are defined or as fallback
  versionProperty?: string; // For jsVersion, global property path if not specified in a pattern
  implies?: string[]; // Technologies implied by this one
  requires?: string[]; // Technologies required for this one to be valid
  requiresCategory?: string[]; // Categories, one of which must have a detected technology for this signature to be considered.
  excludes?: string[]; // Technologies that this one excludes
}

interface SignaturesDatabase {
  [category: string]: SignatureDefinition[];
}

export interface DetectedTechnologyInfo {
  id?: string;
  technology: string;
  version: string | null;
  confidence: number; // 0-100
  isHarmful?: boolean;
  detectionMethod?: string;
  category?: string;
  matchedValue?: string;
  website?: string;
  icon?: string;
}


// --- Signatures Database ---
// Simplified for brevity, expand with Wappalyzer-like details
const signatures: SignaturesDatabase = {
  analytics: [
    {
      name: 'Google Analytics',
      website: 'https://marketingplatform.google.com/about/analytics/',
      icon: 'GoogleAnalytics.svg',
      versions: {
        'Universal Analytics': {
          weight: 0.9,
          patterns: [
            { type: 'script', pattern: /www\.google-analytics\.com\/analytics\.js/i, weight: 0.9 },
            { type: 'jsGlobal', pattern: /ga/, weight: 0.8 },
            { type: 'cookie', pattern: /^_ga/, name: '_ga', weight: 0.7 }, // Added name for clarity
            { type: 'cookie', pattern: /^_gid/, name: '_gid', weight: 0.7 },
            { type: 'networkRequest', pattern: /collect\?v=1&_v=j\d+&/i, weight: 0.6 },
          ],
        },
        GA4: {
          weight: 0.95,
          patterns: [
            { type: 'script', pattern: /www\.googletagmanager\.com\/gtag\/js\?id=G-/i, weight: 0.95 },
            { type: 'jsGlobal', pattern: /gtag/, weight: 0.8 },
            { type: 'networkRequest', pattern: /\/g\/collect\?v=2/i, weight: 0.7 },
          ],
        },
      },
      implies: ['Google Tag Manager'], // Example implication
    },
    {
      name: 'Google Tag Manager',
      website: 'https://marketingplatform.google.com/about/tag-manager/',
      icon: 'GoogleTagManager.svg',
      patterns: [
        { type: 'script', pattern: /www\.googletagmanager\.com\/gtm\.js/i, weight: 0.9 },
        { type: 'jsGlobal', pattern: /dataLayer/, weight: 0.8 },
        { type: 'html', pattern: /<!-- Google Tag Manager -->/i, weight: 0.7 },
      ],
    },
     {
      name: "Mixpanel",
      website: "https://mixpanel.com",
      icon: "Mixpanel.svg",
      patterns: [
        { type: "script", pattern: /cdn\.mxpnl\.com\/libs\/mixpanel/i, weight: 0.9 },
        { type: "jsGlobal", pattern: /mixpanel/, weight: 0.8 },
        { type: "cookie", pattern: /^mp_.*_mixpanel$/, name: 'mp_.*_mixpanel', weight: 0.7}, // Regex for cookie name
        { type: "networkRequest", pattern: /api\.mixpanel\.com\/track/i, weight: 0.6 },
      ]
    },
  ],
  cms: [
    {
      name: 'WordPress',
      website: 'https://wordpress.org',
      icon: 'WordPress.svg',
      cpe: 'cpe:/a:wordpress:wordpress',
      oss: true,
      patterns: [
        { type: 'meta', name: 'generator', content: /WordPress (\d+\.\d+(?:\.\d+)?)/i, versionCaptureGroup: 1, weight: 0.95 },
        { type: 'script', pattern: /\/wp-content\//i, weight: 0.8 },
        { type: 'script', pattern: /\/wp-includes\//i, weight: 0.8 },
        { type: 'html', pattern: /class="[^"]*wp-/i, weight: 0.7 },
        { type: 'url', pattern: /\/wp-admin\//i, weight: 0.6},
        { type: 'robots', pattern: /Disallow: \/wp-admin\//i, weight: 0.5}
      ],
      implies: ['PHP', 'MySQL'],
    },
    {
      name: 'Shopify',
      website: 'https://www.shopify.com',
      icon: 'Shopify.svg',
      saas: true,
      pricing: ['mid', 'recurring'],
      patterns: [
          { type: 'script', pattern: /cdn\.shopify\.com/i, weight: 0.9 },
          { type: 'jsGlobal', pattern: /Shopify/, weight: 0.8 },
          { type: 'html', pattern: /Shopify\.theme/i, weight: 0.7},
          { type: 'cookie', pattern: /^_shopify_/, name: '_shopify_.*', weight: 0.7}, // Example
      ],
      requiresCategory: ['ecommerce_platform'], // Example
  },
  ],
  programming_languages: [
    {
      name: 'PHP',
      website: 'https://www.php.net',
      icon: 'PHP.svg',
      oss: true,
      patterns: [
        { type: 'header', pattern: /x-powered-by/i, value: /PHP\/(\d+\.\d+(?:\.\d+)?)/i, versionCaptureGroup: 1, weight: 0.8 },
        { type: 'cookie', pattern: /PHPSESSID/i, name: 'PHPSESSID', weight: 0.7 },
        { type: 'url', pattern: /\.php(?:\?|$)/i, weight: 0.6 },
      ],
    },
    {
        name: 'Ruby',
        website: 'https://www.ruby-lang.org/',
        icon: 'Ruby.svg',
        patterns: [
            { type: 'header', pattern: /server/i, value: /Phusion Passenger/i, weight: 0.8 },
            { type: 'header', pattern: /x-powered-by/i, value: /Ruby/i, weight: 0.7 },
        ],
    },
  ],
   server_platforms: [
    {
      name: "Nginx",
      website: "https://nginx.org/",
      icon: "Nginx.svg",
      patterns: [
        { type: "header", pattern: /server/i, value: /nginx(?:\/([\d.]+))?/i, versionCaptureGroup: 1, weight: 0.9 }
      ]
    },
    {
      name: "Apache",
      website: "https://httpd.apache.org/",
      icon: "Apache.svg",
      patterns: [
        { type: "header", pattern: /server/i, value: /Apache(?:\/([\d.]+))?/i, versionCaptureGroup: 1, weight: 0.9 }
      ]
    }
  ],
  web_frameworks: [
    {
        name: 'React',
        website: 'https://reactjs.org',
        icon: 'React.svg',
        patterns: [
            { type: 'jsGlobal', pattern: /React/, weight: 0.9 },
            { type: 'dom', pattern: /data-reactroot/i, weight: 0.8 }, // Simple DOM check for attribute
            { type: 'jsVersion', versionProperty: 'React.version', pattern: /(\d+\.\d+\.\d+)/, versionCaptureGroup: 1, weight: 0.9 }
        ],
    },
    {
        name: 'Vue.js',
        website: 'https://vuejs.org',
        icon: 'Vue.svg',
        patterns: [
            { type: 'jsGlobal', pattern: /Vue/, weight: 0.9 },
            { type: 'dom', pattern: /data-v-(?:[a-f0-9]{8}|[a-f0-9]{1,7}(?:-[a-f0-9]{1,})?)/i, weight: 0.8 }, // Vue scoped style attribute
            { type: 'jsVersion', versionProperty: 'Vue.version', pattern: /(\d+\.\d+\.\d+)/, versionCaptureGroup: 1, weight: 0.9 }
        ],
    },
  ],
  // Add more categories and signatures here
  ecommerce_platform: [ // Example category for requiresCategory
    {
        name: 'Generic E-commerce Platform', // Placeholder for demonstration
        patterns: [{type: 'html', pattern: /cart|checkout|product/i, weight: 0.1}]
    }
  ]
};

// --- Helper Functions for Extraction ---

const extractJsVersions = (html: string): Record<string, string | null> => {
  const jsVersions: Record<string, string | null> = {};
  const patterns: Record<string, RegExp> = {
    "React.version": /React\.version\s*=\s*['"]([^'"]+)['"]/i,
    "Vue.version": /Vue\.version\s*=\s*['"]([^'"]+)['"]/i,
    "angular.version": /angular\.version\s*=\s*\{\s*full:\s*['"]([^'"]+)['"]/i,
    "$.fn.jquery": /\$\.fn\.jquery\s*=\s*['"]([^'"]+)['"]/i,
    // Add more version properties here
  };

  for (const prop in patterns) {
    const match = html.match(patterns[prop]);
    jsVersions[prop] = match && match[1] ? match[1] : null;
  }
  return jsVersions;
};

const extractScripts = (html: string): string[] => {
  const scriptsArr: string[] = [];
  const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    scriptsArr.push(match[1]);
  }
  // Consider inline script content for 'scripts' type patterns (different from 'jsGlobal')
  const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  while ((match = inlineScriptRegex.exec(html)) !== null) {
    if (!match[0].includes('src=')) { // Ensure it's not also an external script tag
       scriptsArr.push(match[1]); // Add content of inline scripts
    }
  }
  return scriptsArr;
};

const extractCssLinks = (html: string): string[] => {
  const cssLinksArr: string[] = [];
  const cssRegex = /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = cssRegex.exec(html)) !== null) {
    cssLinksArr.push(match[1]);
  }
  return cssLinksArr;
};

const extractMetaTags = (html: string): Record<string, string> => {
  const metaTagsObj: Record<string, string> = {};
  const metaRegex = /<meta[^>]*?(?:name|property)=["']([^"']+)["'][^>]*?content=["']([^"']*)["'][^>]*?>/gi;
  let match;
  while ((match = metaRegex.exec(html)) !== null) {
    metaTagsObj[match[1].toLowerCase()] = match[2];
  }
  return metaTagsObj;
};

const extractCookies = (pageData: PageContentResult): Array<{ name: string; value: string }> => {
  const cookiesArr: Array<{ name: string; value: string }> = [];
  if (pageData.cookies) { // Cookies from Set-Cookie headers
    const cookieStrings = Array.isArray(pageData.cookies) ? pageData.cookies : pageData.cookies.split(';');
    for (const cookieStr of cookieStrings) {
      const parts = cookieStr.split('=');
      if (parts.length >= 2) {
        cookiesArr.push({ name: parts[0].trim(), value: parts.slice(1).join('=').trim() });
      }
    }
  }
  // Add extraction from document.cookie if running in a context where it's available and relevant (not for server-side fetch)
  if (pageData.html) {
    const docCookieRegex = /document\.cookie\s*=\s*['"]([^'"]+?)=([^;'"]*)/gi;
    let match;
    while ((match = docCookieRegex.exec(pageData.html)) !== null) {
     if (!cookiesArr.some(c => c.name === match[1])) { // Avoid duplicates if already from header
        cookiesArr.push({ name: match[1], value: match[2] });
      }
    }
  }
  return cookiesArr;
};

const extractPotentialJsGlobals = (html: string): string[] => {
  const globals = new Set<string>();
  // Look for assignments like: var X=, window.X=, const X=, let X=
  // And also common library names if they appear as standalone words.
  const globalRegex = /(?:var|let|const|window)\s*([a-zA-Z_$][\w$]*)\s*=/g;
  let match;
  while ((match = globalRegex.exec(html)) !== null) {
    globals.add(match[1]);
  }
  // Check for presence of known library names (this is a heuristic)
  const commonLibs = ['React', 'ReactDOM', 'Vue', 'jQuery', '$', '_', 'angular', 'WPCOMGlobal'];
  commonLibs.forEach(lib => {
    if (new RegExp(`\\b${lib}\\b`).test(html)) {
      globals.add(lib);
    }
  });
  return Array.from(globals);
};

const extractNetworkRequests = (html: string): string[] => {
    const requests = new Set<string>();
    // Simple regex for URLs in strings (e.g., in JavaScript, data attributes)
    const urlRegex = /(['"`])(https?:\/\/[^'"`\s]+)\1/g;
    let match;
    while ((match = urlRegex.exec(html)) !== null) {
        requests.add(match[2]);
    }
    // Add script src attributes
    const scriptSrcRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    while ((match = scriptSrcRegex.exec(html)) !== null) {
        requests.add(match[1]);
    }
    // Add link href attributes (for CSS, etc.)
    const linkHrefRegex = /<link[^>]+href=["']([^"']+)["']/gi;
    while ((match = linkHrefRegex.exec(html)) !== null) {
        requests.add(match[1]);
    }
    return Array.from(requests);
};

const extractHtmlComments = (html: string): string[] => {
  const comments: string[] = [];
  const commentRegex = /<!--([\s\S]*?)-->/gi;
  let match;
  while ((match = commentRegex.exec(html)) !== null) {
    comments.push(match[1].trim());
  }
  return comments;
};

// --- Core Detection Logic ---

function checkPattern(
  patternDef: PatternDefinition,
  html: string,
  scripts: string[],
  cssLinks: string[],
  headers: Record<string, string | string[]>,
  metaTags: Record<string, string>,
  cookies: Array<{ name: string; value: string }>,
  jsGlobals: string[],
  networkRequests: string[],
  htmlComments: string[],
  jsVersions: Record<string, string | null>,
  currentUrl: string,
  robotsTxtContent: string | null
): { match: boolean; version?: string | null; matchedValue?: string } {
  let match = false;
  let version: string | null = null;
  let matchedValue: string | undefined;

  const testAndExtract = (textToTest: string | undefined, regex: RegExp, versionGroup?: number) => {
    if (typeof textToTest !== 'string') return;
    const execResult = regex.exec(textToTest);
    if (execResult) {
      match = true;
      matchedValue = execResult[0];
      if (versionGroup && execResult[versionGroup]) {
        version = execResult[versionGroup];
      }
    }
  };

  switch (patternDef.type) {
    case 'html':
      testAndExtract(html, patternDef.pattern, patternDef.versionCaptureGroup);
      break;
    case 'script': // Matches against script src URLs AND inline script content
      scripts.forEach(s => testAndExtract(s, patternDef.pattern, patternDef.versionCaptureGroup));
      break;
    case 'css': // Matches against CSS file URLs
      cssLinks.forEach(link => testAndExtract(link, patternDef.pattern, patternDef.versionCaptureGroup));
      break;
    case 'header':
      const headerKey = (patternDef.pattern.source.toLowerCase() === 'server' || patternDef.pattern.source.toLowerCase() === 'x-powered-by') ? patternDef.pattern.source.toLowerCase() : patternDef.pattern.source; // common headers
      const headerVal = headers[headerKey] || headers[headerKey.toLowerCase()];
      if (headerVal) {
        const headerValStr = Array.isArray(headerVal) ? headerVal.join(', ') : headerVal;
        if (patternDef.value) {
          testAndExtract(headerValStr, patternDef.value, patternDef.versionCaptureGroup);
        } else {
          match = true; // Header existence is enough
          matchedValue = headerKey;
        }
      }
      break;
    case 'meta':
      const metaName = patternDef.name?.toLowerCase();
      if (metaName && metaTags[metaName]) {
        if (patternDef.content) {
          testAndExtract(metaTags[metaName], patternDef.content, patternDef.versionCaptureGroup);
        } else {
          match = true;
          matchedValue = metaName;
        }
      }
      break;
    case 'cookie':
        cookies.forEach(cookie => {
            // Match cookie name if patternDef.name is provided, otherwise patternDef.pattern is for the name
            const nameToTest = patternDef.name ? cookie.name : cookie.name;
            const patternForName = patternDef.name ? new RegExp(patternDef.name) : patternDef.pattern;

            if (patternForName.test(nameToTest)) {
                if (patternDef.value) { // If a value regex is also provided
                    testAndExtract(cookie.value, patternDef.value, patternDef.versionCaptureGroup);
                } else {
                    match = true;
                    matchedValue = cookie.name;
                }
            }
        });
        break;
    case 'jsGlobal':
      if (jsGlobals.some(g => patternDef.pattern.test(g))) {
        match = true;
        const matchedGlobal = jsGlobals.find(g => patternDef.pattern.test(g));
        matchedValue = matchedGlobal;
      }
      break;
    case 'networkRequest':
      networkRequests.forEach(req => testAndExtract(req, patternDef.pattern, patternDef.versionCaptureGroup));
      break;
    case 'jsVersion':
      if (patternDef.versionProperty && jsVersions[patternDef.versionProperty]) {
        const verStr = jsVersions[patternDef.versionProperty];
        if (verStr) {
          testAndExtract(verStr, patternDef.pattern, patternDef.versionCaptureGroup || 1);
        }
      }
      break;
    case 'htmlComment':
      htmlComments.forEach(comment => testAndExtract(comment, patternDef.pattern, patternDef.versionCaptureGroup));
      break;
    case 'error': // Basic error pattern check in HTML
      testAndExtract(html, patternDef.pattern, patternDef.versionCaptureGroup);
      break;
    case 'url':
      testAndExtract(currentUrl, patternDef.pattern, patternDef.versionCaptureGroup);
      break;
    case 'robots':
      if (robotsTxtContent) {
        testAndExtract(robotsTxtContent, patternDef.pattern, patternDef.versionCaptureGroup);
      }
      break;
    case 'dom': // Simplified DOM check using regex on HTML
      // patternDef.pattern would be a regex for the element structure
      // patternDef.attributes could check for attribute presence/values within that structure (complex regex needed)
      // patternDef.text could check for text content (complex regex needed)
      // This is a placeholder for a more robust DOM analysis if possible with regex.
      // For now, it behaves like 'html' type for existence.
      testAndExtract(html, patternDef.pattern, patternDef.versionCaptureGroup);
      if (match && patternDef.attributes) {
        let allAttrsMatch = true;
        const matchedOuterHTML = html.match(patternDef.pattern)?.[0] || "";
        for (const attrName in patternDef.attributes) {
            const attrPattern = new RegExp(`${attrName}=["']([^"']*)["']`, 'i');
            const attrMatch = matchedOuterHTML.match(attrPattern);
            if (!attrMatch || !patternDef.attributes[attrName].test(attrMatch[1])) {
                allAttrsMatch = false;
                break;
            }
        }
        if (!allAttrsMatch) match = false;
      }
      break;
    default:
      match = false;
  }
  return { match, version, matchedValue };
}

export async function detectTechnologies(
  pageData: PageContentResult,
  finalUrl: string
): Promise<DetectedTechnologyInfo[]> {
  let detectedTechMap: Map<string, DetectedTechnologyInfo> = new Map();

  if (!pageData.html) {
    // Optionally return an error or an empty array with a specific message
    // For now, returning empty if no HTML.
    return [];
  }

  const html = pageData.html;
  const headers = pageData.headers || {};
  const scripts = extractScripts(html);
  const cssLinks = extractCssLinks(html);
  const metaTags = extractMetaTags(html);
  const cookies = extractCookies(pageData);
  const jsGlobals = extractPotentialJsGlobals(html);
  const networkRequests = extractNetworkRequests(html);
  const htmlComments = extractHtmlComments(html);
  const jsVersions = extractJsVersions(html);

  let robotsTxtContent: string | null = null;
  // Check if any signature uses 'robots' type, then fetch
  const hasRobotsPattern = Object.values(signatures).flat().some(sig =>
    (sig.patterns || []).some(p => p.type === 'robots') ||
    Object.values(sig.versions || {}).some(v => v.patterns.some(p => p.type === 'robots'))
  );

  if (hasRobotsPattern) {
    try {
      const urlObj = new URL(finalUrl);
      robotsTxtContent = await retrieveRobotsTxt(`${urlObj.protocol}//${urlObj.hostname}`);
    } catch (e) {
      console.warn(`[Signatures] Failed to fetch or parse robots.txt for ${finalUrl}:`, e);
    }
  }


  for (const categoryName in signatures) {
    for (const sigDef of signatures[categoryName]) {
      let overallConfidence = 0;
      let detectedVersion: string | null = null;
      let primaryMatchedValue: string | undefined;
      let primaryDetectionMethod: string | undefined;
      let matchOccurred = false;

      const processPatterns = (patterns: PatternDefinition[] | undefined, baseWeight: number) => {
        if (!patterns) return;
        for (const pDef of patterns) {
          const result = checkPattern(pDef, html, scripts, cssLinks, headers, metaTags, cookies, jsGlobals, networkRequests, htmlComments, jsVersions, finalUrl, robotsTxtContent);
          if (result.match) {
            matchOccurred = true;
            // Confidence: pattern weight or base signature weight
            const currentPatternConfidence = (pDef.weight !== undefined ? pDef.weight : sigDef.weight !== undefined ? sigDef.weight : 0.5) * baseWeight;
            overallConfidence = Math.max(overallConfidence, currentPatternConfidence);

            if (result.version && (!detectedVersion || currentPatternConfidence > overallConfidence * 0.8)) { // Prioritize version from higher confidence pattern
              detectedVersion = result.version;
            }
            if (result.matchedValue && (!primaryMatchedValue || currentPatternConfidence > overallConfidence * 0.8)) {
              primaryMatchedValue = result.matchedValue;
              primaryDetectionMethod = `Pattern Type: ${pDef.type}, Matched: ${pDef.pattern.source.substring(0,50)}`;
            }
          }
        }
      };

      if (sigDef.versions) {
        for (const versionName in sigDef.versions) {
          if (versionName === 'patterns' || versionName === 'versionProperty') continue; // Skip special keys
          const versionSig = sigDef.versions[versionName];
          let versionSpecificMatchOccurred = false;
          let versionSpecificConfidence = 0;
          let versionSpecificDetectedVersion: string | null = null; // Version name from key
          let versionSpecificPrimaryMV: string | undefined;
          let versionSpecificPrimaryDM: string | undefined;


          // Temporarily store results for this specific version signature
            let tempMatchOccurred = false;
            let tempConfidence = 0;
            let tempDetectedVersion: string | null = null;
            let tempMatchedValue: string | undefined;
            let tempDetectionMethod: string | undefined;

            for (const pDef of versionSig.patterns) {
                 const result = checkPattern(pDef, html, scripts, cssLinks, headers, metaTags, cookies, jsGlobals, networkRequests, htmlComments, jsVersions, finalUrl, robotsTxtContent);
                 if (result.match) {
                    tempMatchOccurred = true;
                    const patternConfidence = (pDef.weight !== undefined ? pDef.weight : (versionSig.weight !== undefined ? versionSig.weight : 0.6));
                    tempConfidence = Math.max(tempConfidence, patternConfidence);
                    if (result.version && (!tempDetectedVersion || patternConfidence > tempConfidence * 0.8)) {
                        tempDetectedVersion = result.version;
                    }
                    if (result.matchedValue && (!tempMatchedValue || patternConfidence > tempConfidence * 0.8)) {
                        tempMatchedValue = result.matchedValue;
                        tempDetectionMethod = `Version '${versionName}' Pattern: ${pDef.type}, Matched: ${pDef.pattern.source.substring(0,30)}`;
                    }
                 }
            }

            if (tempMatchOccurred && tempConfidence > overallConfidence) {
                matchOccurred = true;
                overallConfidence = tempConfidence;
                detectedVersion = tempDetectedVersion || versionName; // Use pattern's version or the version key
                primaryMatchedValue = tempMatchedValue;
                primaryDetectionMethod = tempDetectionMethod;
            }
        }
         // Process general patterns if defined within sigDef.versions (as a fallback or addition)
        if (sigDef.versions.patterns) {
            processPatterns(sigDef.versions.patterns, sigDef.weight || 0.5);
        }

      } else if (sigDef.patterns) {
        processPatterns(sigDef.patterns, sigDef.weight || 0.5);
      }

      // Try jsVersionProperty if no version found yet and property exists
      if (!detectedVersion && sigDef.versionProperty && jsVersions[sigDef.versionProperty]) {
        detectedVersion = jsVersions[sigDef.versionProperty];
        if (!primaryDetectionMethod && detectedVersion) {
            primaryDetectionMethod = `JS Version Property: ${sigDef.versionProperty}`;
            primaryMatchedValue = detectedVersion;
        }
      }


      if (matchOccurred && overallConfidence > 0.1) { // Threshold for detection
        const existing = detectedTechMap.get(sigDef.name);
        if (!existing || overallConfidence > (existing.confidence / 100)) {
          detectedTechMap.set(sigDef.name, {
            technology: sigDef.name,
            version: detectedVersion,
            confidence: Math.min(100, Math.round(overallConfidence * 100)),
            category: categoryName,
            website: sigDef.website,
            icon: sigDef.icon,
            matchedValue: primaryMatchedValue,
            detectionMethod: primaryDetectionMethod,
            // Store implies/excludes for post-processing
            _meta: { implies: sigDef.implies, excludes: sigDef.excludes, requires: sigDef.requires, requiresCategory: sigDef.requiresCategory }
          });
        }
      }
    }
  }

  // --- Post-processing Pass ---
  let finalDetections = Array.from(detectedTechMap.values());

  // 1. Apply 'requires' and 'requiresCategory'
  finalDetections = finalDetections.filter(tech => {
    const meta = (tech as any)._meta;
    if (!meta) return true; // Should not happen if set correctly

    if (meta.requires) {
      if (!meta.requires.every((reqName: string) => detectedTechMap.has(reqName))) {
        return false; // Requirement not met
      }
    }
    if (meta.requiresCategory) {
      if (!meta.requiresCategory.some((reqCat: string) =>
        finalDetections.some(d => d.category === reqCat && d.technology !== tech.technology) // Check other detected techs
      )) {
        return false; // Category requirement not met
      }
    }
    return true;
  });
  // Rebuild map after filtering
  detectedTechMap = new Map(finalDetections.map(t => [t.technology, t]));


  // 2. Apply 'excludes'
  const excludedTechNames = new Set<string>();
  for (const tech of finalDetections) {
    const meta = (tech as any)._meta;
    if (meta?.excludes) {
      meta.excludes.forEach((exName: string) => {
        if (detectedTechMap.has(exName)) {
          // Basic exclusion: if tech A excludes B, and B is found, remove B.
          // More complex logic could consider confidence.
          excludedTechNames.add(exName);
        }
      });
    }
  }
  finalDetections = finalDetections.filter(tech => !excludedTechNames.has(tech.technology));
  // Rebuild map
  detectedTechMap = new Map(finalDetections.map(t => [t.technology, t]));


  // 3. Apply 'implies'
  const impliedDetections: DetectedTechnologyInfo[] = [];
  for (const tech of finalDetections) {
    const meta = (tech as any)._meta;
    if (meta?.implies) {
      meta.implies.forEach((impliedName: string) => {
        if (!detectedTechMap.has(impliedName)) {
          // Find original signature for implied tech to get its details
          let impliedSigDef: SignatureDefinition | undefined;
          for (const cat in signatures) {
            impliedSigDef = signatures[cat].find(s => s.name === impliedName);
            if (impliedSigDef) break;
          }
          if (impliedSigDef) {
            impliedDetections.push({
              technology: impliedName,
              version: null, // Implied tech version is not directly known from implication
              confidence: Math.round(tech.confidence * 0.7), // Implied confidence is lower
              category: Object.keys(signatures).find(cat => signatures[cat].some(s => s.name === impliedName)),
              website: impliedSigDef.website,
              icon: impliedSigDef.icon,
              detectionMethod: `Implied by ${tech.technology}`,
              _meta: {} // Clear meta for implied
            });
          }
        }
      });
    }
  }
  // Add implied detections if they are not already present
  impliedDetections.forEach(implied => {
    if (!detectedTechMap.has(implied.technology)) {
      finalDetections.push(implied);
      detectedTechMap.set(implied.technology, implied); // Add to map for subsequent implies checks
    }
  });

  // Clean up _meta field
  return finalDetections.map(tech => {
    const { _meta, ...rest } = tech as any;
    return rest;
  });
}
