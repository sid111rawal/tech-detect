/**
 * TechDetective - Technology Signatures
 * This file contains the signature database for detecting web technologies.
 */

import type { PageContentResult } from '@/services/page-retriever';
import { retrieveRobotsTxt } from '@/services/page-retriever'; // Assuming this path

// --- Type Definitions ---

// Details forimplies, requires, excludes patterns
interface ImplyDetail {
  name: string;
  confidence?: number; // 0-100, how much this implication affects confidence
}

// Detail for patterns that include version and confidence
interface PatternDetail {
  pattern: string; // Regex string
  confidence?: number; // 0-100
  version?: string; // Version extraction string (e.g., \\1)
}

// For DOM selectors, specifying what to check
interface DomSelectorTarget {
  exists?: string; // Empty string if just existence, or regex for specific outerHTML
  attributes?: Record<string, string>; // attribute_name -> regex for value
  properties?: Record<string, string>; // property_name -> regex for value
  text?: string; // regex for text content
  confidence?: number; // 0-100
}

interface PatternDefinition {
  type: 'htmlContent' | 'scriptSrc' | 'scriptContent' | 'css' | 'header' | 'metaName' | 'metaProperty' | 'cookie' | 'jsGlobal' | 'networkRequest' | 'jsVersion' | 'htmlComment' | 'robots' | 'url' | 'domQuerySelector';
  pattern?: RegExp;                 // For most types (e.g. html, scriptSrc, scriptContent, css, jsGlobal, networkRequest, htmlComment, robots, url)
  name?: string;                    // For metaName, cookie name, header key
  contentPattern?: RegExp;          // For meta content
  valuePattern?: RegExp;            // For header value
  versionProperty?: string;         // For jsVersion (e.g., "$.fn.jquery")
  versionCaptureGroup?: number;     // Index of the regex capture group for version (1-based)
  selector?: string;                // For domQuerySelector
  attributeName?: string;           // For domQuerySelector attribute check
  attributeValuePattern?: RegExp;   // For domQuerySelector attribute value check
  textContentPattern?: RegExp;      // For domQuerySelector text content check
  weight?: number;                  // Confidence weight for this specific pattern (0.0 to 1.0)
  detectionMethod?: string;         // Custom description of how this pattern works
  // For extracting a specific matched value, e.g., the script URL or the header value string.
  // The input type depends on what checkPattern provides for that type.
  matchedValueExtractor?: (execResult: RegExpExecArray | Element | { name: string, value: string } | string) => string;
}


interface VersionSignatureDetail {
  confidence?: number; // Overall weight/base confidence for this version if its patterns match (0-100)
  additionalPatterns: PatternDefinition[];
}

interface SignatureDefinition {
  name: string;
  website?: string;
  icon?: string;
  cpe?: string;
  saas?: boolean;
  oss?: boolean;
  pricing?: string[]; // e.g., "low", "mid", "high", "freemium", "recurring"
  categories?: string[]; // e.g., "CMS", "Analytics", "JavaScript Frameworks"

  confidence?: number; // Default base confidence (0-100) if not specified by patterns

  // Wappalyzer-style simple patterns (currently less used by detectTechnologies's main loop)
  js?: Record<string, string | { version?: string; confidence?: number }>; // globalVar: "" or { version: "\\1", confidence: 50 }
  headers?: Record<string, string>; // headerName: "regex for value"
  cookies?: Record<string, string>; // cookieName: "regex for value"
  dom?: Record<string, DomSelectorTarget>; // querySelector: {exists: "", text: "regex", attributes: {"attr": "regex"}}
  meta?: Record<string, string>; // metaName: "regex for content"
  html?: PatternDetail[] | string[] | string; // Can be array of PatternDetail, array of regex strings, or single regex string
  scriptSrc?: PatternDetail[] | string[] | string;
  scripts?: PatternDetail[] | string[] | string; // For inline script content
  url?: PatternDetail[] | string[] | string;
  robots?: PatternDetail[] | string[] | string;
  css?: PatternDetail[] | string[] | string; // For inline CSS content or matched CSS rules
  xhr?: PatternDetail[] | string[] | string; // For XHR/fetch request URLs
  dns?: Record<string, string[]>; // e.g. { "MX": ["example\\.com"] } // Note: DNS checks are not implemented in retrievePageContent
  probe?: Record<string, string>; // path: "regex for content" // Note: Probing is not implemented

  // Complex patterns and version definitions (primarily used by detectTechnologies)
  additionalPatterns?: PatternDefinition[];
  versions?: Record<string, VersionSignatureDetail>; // Key is version name (e.g., "6.x")

  implies?: (string | ImplyDetail)[];
  requires?: (string | ImplyDetail)[];
  requiresCategory?: string[];
  excludes?: (string | ImplyDetail)[];
}


interface SignaturesDatabase {
  [category: string]: SignatureDefinition[];
}

export interface DetectedTechnologyInfo {
  id?: string; // Optional unique ID for the detection rule/signature if applicable
  technology: string;
  version: string | null;
  confidence: number; // 0-100
  isHarmful?: boolean; // If the technology is known to be harmful or outdated
  detectionMethod?: string; // How this technology was identified (e.g., "Signature: React (scriptSrc)", "Header: X-Powered-By")
  category?: string; // Main category from SignaturesDatabase
  categories?: string[]; // All associated categories
  matchedValue?: string; // The actual string value from the source that matched a pattern
  website?: string;
  icon?: string;
  // Internal meta for processing, not for final output
  _meta?: {
    implies?: (string | ImplyDetail)[];
    requires?: (string | ImplyDetail)[];
    requiresCategory?: string[];
    excludes?: (string | ImplyDetail)[];
  };
}

// --- Signatures Database ---
const signatures: SignaturesDatabase = {
  analytics: [
    {
      name: 'Google Analytics',
      website: 'https://marketingplatform.google.com/about/analytics/',
      icon: 'GoogleAnalytics.svg',
      categories: ['Analytics', 'Audience Measurement'],
      versions: {
        'Universal Analytics': {
          confidence: 90,
          additionalPatterns: [
            { type: 'scriptSrc', pattern: /www\.google-analytics\.com\/analytics\.js/i, weight: 0.9, detectionMethod: "UA Script: analytics.js" },
            { type: 'jsGlobal', pattern: /^ga$/, weight: 0.8, detectionMethod: "UA Global: ga" },
            { type: 'cookie', name: '_ga', weight: 0.7, detectionMethod: "UA Cookie: _ga" },
            { type: 'cookie', name: '_gid', weight: 0.7, detectionMethod: "UA Cookie: _gid" },
            { type: 'networkRequest', pattern: /collect\?v=1&_v=j\d+&/i, weight: 0.6, detectionMethod: "UA Beacon: v=1" },
          ],
        },
        'GA4': {
          confidence: 95,
          additionalPatterns: [
            { type: 'scriptSrc', pattern: /www\.googletagmanager\.com\/gtag\/js\?id=G-/i, weight: 0.95, detectionMethod: "GA4 Script: gtag.js id=G-" },
            { type: 'jsGlobal', pattern: /^gtag$/, weight: 0.8, detectionMethod: "GA4 Global: gtag" },
            { type: 'networkRequest', pattern: /\/g\/collect\?v=2/i, weight: 0.7, detectionMethod: "GA4 Beacon: v=2" },
          ],
        },
      },
      implies: [{ name: 'Google Tag Manager', confidence: 70 }],
    },
    {
      name: 'Google Tag Manager',
      website: 'https://marketingplatform.google.com/about/tag-manager/',
      icon: 'GoogleTagManager.svg',
      categories: ['Analytics', 'Tag Management'],
      additionalPatterns: [
        { type: 'scriptSrc', pattern: /www\.googletagmanager\.com\/gtm\.js/i, weight: 0.9, detectionMethod: "GTM Script: gtm.js" },
        { type: 'jsGlobal', pattern: /^dataLayer$/, weight: 0.8, detectionMethod: "GTM Global: dataLayer" },
        { type: 'htmlComment', pattern: /Google Tag Manager/i, weight: 0.7, detectionMethod: "GTM HTML Comment" },
      ],
    },
     {
      name: "Mixpanel",
      website: "https://mixpanel.com",
      icon: "Mixpanel.svg",
      categories: ['Analytics'],
      additionalPatterns: [
        { type: "scriptSrc", pattern: /cdn\.mxpnl\.com\/libs\/mixpanel/i, weight: 0.9, detectionMethod: "Mixpanel Script CDN" },
        { type: "jsGlobal", pattern: /^mixpanel$/, weight: 0.8, detectionMethod: "Mixpanel Global: mixpanel" },
        { type: "cookie", name: 'mp_.*_mixpanel', pattern: /^mp_.*_mixpanel$/, weight: 0.7, detectionMethod: "Mixpanel Cookie pattern"}, // Regex for cookie name
        { type: "networkRequest", pattern: /api\.mixpanel\.com\/track/i, weight: 0.6, detectionMethod: "Mixpanel API Request" },
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
      categories: ['CMS', 'Blogs'],
      additionalPatterns: [
        { type: 'metaName', name: 'generator', contentPattern: /WordPress (\d+\.\d+(?:\.\d+)?)/i, versionCaptureGroup: 1, weight: 0.95, detectionMethod: "WP Meta Generator" },
        { type: 'scriptSrc', pattern: /\/wp-content\//i, weight: 0.8, detectionMethod: "WP Script Path: /wp-content/" },
        { type: 'scriptSrc', pattern: /\/wp-includes\//i, weight: 0.8, detectionMethod: "WP Script Path: /wp-includes/" },
        { type: 'htmlContent', pattern: /class="[^"]*wp-/i, weight: 0.7, detectionMethod: "WP HTML Class prefix" },
        { type: 'url', pattern: /\/wp-admin\//i, weight: 0.6, detectionMethod: "WP URL Path: /wp-admin/"},
        { type: 'robots', pattern: /Disallow: \/wp-admin\//i, weight: 0.5, detectionMethod: "WP Robots.txt: /wp-admin/"}
      ],
      implies: ['PHP', 'MySQL'],
    },
    {
      name: 'Shopify',
      website: 'https://www.shopify.com',
      icon: 'Shopify.svg',
      saas: true,
      pricing: ['mid', 'recurring'],
      categories: ['CMS', 'Ecommerce'],
      additionalPatterns: [
          { type: 'scriptSrc', pattern: /cdn\.shopify\.com/i, weight: 0.9, detectionMethod: "Shopify Script CDN" },
          { type: 'jsGlobal', pattern: /^Shopify$/, weight: 0.8, detectionMethod: "Shopify Global: Shopify" },
          { type: 'htmlContent', pattern: /Shopify\.theme/i, weight: 0.7, detectionMethod: "Shopify HTML content: Shopify.theme"},
          { type: 'cookie', name: '_shopify_.*', pattern: /^_shopify_/, weight: 0.7, detectionMethod: "Shopify Cookie prefix"}, 
      ],
      requiresCategory: ['ecommerce_platform'], 
  },
  ],
  programming_languages: [
    {
      name: 'PHP',
      website: 'https://www.php.net',
      icon: 'PHP.svg',
      oss: true,
      categories: ['Programming Languages'],
      additionalPatterns: [
        { type: 'header', name: 'x-powered-by', valuePattern: /PHP\/(\d+\.\d+(?:\.\d+)?)/i, versionCaptureGroup: 1, weight: 0.8, detectionMethod: "PHP Header: X-Powered-By" },
        { type: 'cookie', name: 'PHPSESSID', weight: 0.7, detectionMethod: "PHP Cookie: PHPSESSID" },
        { type: 'url', pattern: /\.php(?:\?|$)/i, weight: 0.6, detectionMethod: "PHP URL Extension: .php" },
      ],
    },
    {
        name: 'Ruby',
        website: 'https://www.ruby-lang.org/',
        icon: 'Ruby.svg',
        categories: ['Programming Languages'],
        additionalPatterns: [
            { type: 'header', name: 'server', valuePattern: /Phusion Passenger/i, weight: 0.8, detectionMethod: "Ruby Header: Phusion Passenger Server" },
            { type: 'header', name: 'x-powered-by', valuePattern: /Ruby/i, weight: 0.7, detectionMethod: "Ruby Header: X-Powered-By Ruby" },
        ],
    },
  ],
   server_platforms: [
    {
      name: "Nginx",
      website: "https://nginx.org/",
      icon: "Nginx.svg",
      categories: ['Web Servers'],
      additionalPatterns: [
        { type: "header", name: "server", valuePattern: /nginx(?:\/([\d.]+))?/i, versionCaptureGroup: 1, weight: 0.9, detectionMethod: "Nginx Server Header" }
      ]
    },
    {
      name: "Apache",
      website: "https://httpd.apache.org/",
      icon: "Apache.svg",
      categories: ['Web Servers'],
      additionalPatterns: [
        { type: "header", name: "server", valuePattern: /Apache(?:\/([\d.]+))?/i, versionCaptureGroup: 1, weight: 0.9, detectionMethod: "Apache Server Header" }
      ]
    }
  ],
  web_frameworks: [
    {
      name: 'React',
      website: 'https://reactjs.org',
      icon: 'React.svg',
      categories: ['JavaScript Frameworks', 'UI Frameworks'],
      cpe: 'cpe:/a:facebook:react',
      implies: ['JavaScript'],
      additionalPatterns: [
        { type: 'jsGlobal', pattern: /^React$/, weight: 0.9, detectionMethod: "Global var: React" },
        { type: 'jsGlobal', pattern: /^ReactDOM$/, weight: 0.8, detectionMethod: "Global var: ReactDOM" },
        { type: 'domQuerySelector', selector: '[data-reactroot]', weight: 0.7, detectionMethod: "DOM attribute: data-reactroot" },
        { type: 'domQuerySelector', selector: '[data-reactid]', weight: 0.6, detectionMethod: "DOM attribute: data-reactid (older)" },
        { type: 'scriptSrc', pattern: /react\.production(?:-\d+)?(\.min)?\.js/i, weight: 0.85, detectionMethod: "Script name: react.production.min.js" },
        { type: 'scriptSrc', pattern: /react-dom\.production(?:-\d+)?(\.min)?\.js/i, weight: 0.85, detectionMethod: "Script name: react-dom.production.min.js" },
        { type: 'jsVersion', versionProperty: 'React.version', pattern: /(\d+\.\d+\.\d+)/, versionCaptureGroup: 1, weight: 0.95, detectionMethod: "JS Version: React.version" },
        { type: 'htmlContent', pattern: /__REACT_DEVTOOLS_GLOBAL_HOOK__/i, weight: 0.5, detectionMethod: "HTML content: __REACT_DEVTOOLS_GLOBAL_HOOK__ (dev)" },
        { type: 'scriptContent', pattern: /createElement\s*\(\s*["']div["']\s*,\s*\{[^}]*id\s*:\s*["']root["']/, weight: 0.4, detectionMethod: "Script content: React.createElement for root" }, // Heuristic for typical React setup
        { type: 'scriptContent', pattern: /react-root/i, weight: 0.4, detectionMethod: "Script content: 'react-root' string literal" },
      ]
    },
    {
        name: 'Vue.js',
        website: 'https://vuejs.org',
        icon: 'Vue.svg',
        categories: ['JavaScript Frameworks', 'UI Frameworks'],
        additionalPatterns: [
            { type: 'jsGlobal', pattern: /^Vue$/, weight: 0.9, detectionMethod: "Vue.js Global: Vue" },
            { type: 'domQuerySelector', selector: '[data-v-(?:[a-f0-9]{8}|[a-f0-9]{1,7}(?:-[a-f0-9]{1,})?)]', weight: 0.8, detectionMethod:"Vue.js DOM attribute: data-v-" }, // Vue scoped style attribute
            { type: 'jsVersion', versionProperty: 'Vue.version', pattern: /(\d+\.\d+\.\d+)/, versionCaptureGroup: 1, weight: 0.9, detectionMethod: "Vue.js Version: Vue.version" },
            { type: 'htmlContent', pattern: /<div id=["']app["']>/i, weight: 0.5, detectionMethod: "Vue.js HTML: <div id='app'>" }, // Common Vue root element
        ],
    },
  ],
  ecommerce_platform: [ 
    {
        name: 'Generic E-commerce Platform', 
        categories: ['Ecommerce'],
        confidence: 10, // Low confidence, just a category marker
        additionalPatterns: [{type: 'htmlContent', pattern: /cart|checkout|product|basket|order/i, weight: 0.1, detectionMethod: "Generic E-commerce keyword in HTML"}]
    }
  ],
  build_tools: [
    {
      name: 'Webpack',
      website: 'https://webpack.js.org/',
      icon: 'Webpack.svg',
      categories: ['Build Tools', 'JavaScript Compilers', 'Module Bundlers'],
      additionalPatterns: [
        { type: 'jsGlobal', pattern: /webpackJsonp/, weight: 0.8, detectionMethod: "Global var: webpackJsonp" },
        { type: 'jsGlobal', pattern: /__webpack_require__/, weight: 0.7, detectionMethod: "Global var: __webpack_require__" },
        { type: 'scriptSrc', pattern: /webpack-runtime(?:-\w+)?\.js/i, weight: 0.6, detectionMethod: "Script name: webpack-runtime" },
        { type: 'scriptSrc', pattern: /(?:bundle|main|chunk)(?:\.[0-9a-fA-F]+)?\.js/i, weight: 0.4, detectionMethod: "Script name: common bundle/chunk pattern (heuristic)" }, // More generic
        { type: 'scriptSrc', pattern: /\/\d+\.[0-9a-fA-F]+\.chunk\.js/i, weight: 0.5, detectionMethod: "Script name: webpack numbered chunk pattern" },
        { type: 'htmlComment', pattern: /webpack.+bundle/i, weight: 0.4, detectionMethod: "HTML Comment: webpack bundle" },
        { type: 'scriptContent', pattern: /webpackBootstrap/i, weight: 0.6, detectionMethod: "Script content: webpackBootstrap function"},
        { type: 'scriptContent', pattern: /__webpack_modules__/i, weight: 0.6, detectionMethod: "Script content: __webpack_modules__ object"},
      ]
    }
  ]
};

// --- Helper Functions for Extraction --- (Ensure these are robust)

const extractJsVersions = (pageData: PageContentResult): Record<string, string | null> => {
  const jsVersions: Record<string, string | null> = {};
  if (!pageData.html) return jsVersions;

  const patterns: Record<string, RegExp> = {
    "React.version": /React\.version\s*=\s*['"]([^'"]+)['"]/i,
    "Vue.version": /Vue\.version\s*=\s*['"]([^'"]+)['"]/i,
    "angular.version": /angular\.version\s*=\s*\{\s*full:\s*['"]([^'"]+)['"]/i,
    "$.fn.jquery": /\$\.fn\.jquery\s*=\s*['"]([^'"]+)['"]/i,
    // Add more version properties here
  };

  for (const prop in patterns) {
    const match = pageData.html.match(patterns[prop]);
    jsVersions[prop] = match && match[1] ? match[1] : null;
  }
  return jsVersions;
};

const extractScripts = (pageData: PageContentResult): {src: string[], content: string[]} => {
  const scriptsArr: {src: string[], content: string[]} = {src: [], content: []};
  if (!pageData.html) return scriptsArr;

  const scriptSrcRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = scriptSrcRegex.exec(pageData.html)) !== null) {
    scriptsArr.src.push(match[1]);
  }
  
  const inlineScriptRegex = /<script(?![^>]*type\s*=\s*(['"])text\/template\1|application\/ld\+json\1)(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi;
  while ((match = inlineScriptRegex.exec(pageData.html)) !== null) {
    if (match[2] && match[2].trim().length > 0) {
       scriptsArr.content.push(match[2].trim());
    }
  }
  return scriptsArr;
};

const extractCssLinks = (pageData: PageContentResult): string[] => {
  const cssLinksArr: string[] = [];
   if (!pageData.html) return cssLinksArr;
  const cssRegex = /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = cssRegex.exec(pageData.html)) !== null) {
    cssLinksArr.push(match[1]);
  }
  return cssLinksArr;
};

const extractMetaTags = (pageData: PageContentResult): {name: Record<string, string>, property: Record<string, string>} => {
  const metaTagsObj: {name: Record<string, string>, property: Record<string, string>} = {name: {}, property: {}};
  if (!pageData.html) return metaTagsObj;

  const metaNameRegex = /<meta[^>]*?name=["']([^"']+)["'][^>]*?content=["']([^"']*)["'][^>]*?>/gi;
  let match;
  while ((match = metaNameRegex.exec(pageData.html)) !== null) {
    metaTagsObj.name[match[1].toLowerCase()] = match[2];
  }
  const metaPropRegex = /<meta[^>]*?property=["']([^"']+)["'][^>]*?content=["']([^"']*)["'][^>]*?>/gi;
  while ((match = metaPropRegex.exec(pageData.html)) !== null) {
    metaTagsObj.property[match[1].toLowerCase()] = match[2];
  }
  return metaTagsObj;
};

const extractCookies = (pageData: PageContentResult): Array<{ name: string; value: string }> => {
  const cookiesArr: Array<{ name: string; value: string }> = [];
  if (pageData.cookies) { 
    const cookieStrings = Array.isArray(pageData.cookies) ? pageData.cookies : pageData.cookies.split(';');
    for (const cookieStr of cookieStrings) {
      const parts = cookieStr.split('=');
      if (parts.length >= 2) {
        cookiesArr.push({ name: parts[0].trim(), value: parts.slice(1).join('=').trim() });
      }
    }
  }
  // Client-side document.cookie (only if running in browser context, less relevant for server-side fetcher)
  // For server-side, this part can be removed or adapted if HTML might contain JS that sets cookies
  if (pageData.html) {
    const docCookieRegex = /document\.cookie\s*=\s*['"]([^'"]+?)=([^;'"]*)/gi;
    let match;
    while ((match = docCookieRegex.exec(pageData.html)) !== null) {
     if (!cookiesArr.some(c => c.name === match[1])) { 
        cookiesArr.push({ name: match[1], value: match[2] });
      }
    }
  }
  return cookiesArr;
};

const extractPotentialJsGlobals = (pageData: PageContentResult): string[] => {
  const globals = new Set<string>();
  if (!pageData.html) return [];
  
  // Look for assignments like: var X=, window.X=, const X=, let X=
  const globalRegex = /(?:var|let|const|window)\s*([a-zA-Z_$][\w$]*)\s*=/g;
  let match;
  while ((match = globalRegex.exec(pageData.html)) !== null) {
    globals.add(match[1]);
  }
  // Check for presence of known library names (this is a heuristic)
  const commonLibs = ['React', 'ReactDOM', 'Vue', 'jQuery', '$', '_', 'angular', 'WPCOMGlobal', 'Shopify', 'gtag', 'ga', 'mixpanel', 'dataLayer', 'webpackJsonp', '__webpack_require__'];
  commonLibs.forEach(lib => {
    // Use a word boundary regex to avoid matching substrings
    if (new RegExp(`\\b${lib.replace('$', '\\$')}\\b`).test(pageData.html!)) {
      globals.add(lib);
    }
  });
  return Array.from(globals);
};

const extractNetworkRequests = (pageData: PageContentResult): string[] => {
    const requests = new Set<string>();
    if (!pageData.html) return [];
    
    // Simple regex for URLs in strings (e.g., in JavaScript, data attributes)
    const urlRegex = /(['"`])(https?:\/\/[^'"`\s]+)\1/g;
    let match;
    while ((match = urlRegex.exec(pageData.html)) !== null) {
        requests.add(match[2]);
    }
    // Add script src attributes
    const scriptSrcRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    while ((match = scriptSrcRegex.exec(pageData.html)) !== null) {
        requests.add(match[1]);
    }
    // Add link href attributes (for CSS, etc.)
    const linkHrefRegex = /<link[^>]+href=["']([^"']+)["']/gi;
    while ((match = linkHrefRegex.exec(pageData.html)) !== null) {
        requests.add(match[1]);
    }
    return Array.from(requests);
};

const extractHtmlComments = (pageData: PageContentResult): string[] => {
  const comments: string[] = [];
  if (!pageData.html) return comments;
  const commentRegex = /<!--([\s\S]*?)-->/gi;
  let match;
  while ((match = commentRegex.exec(pageData.html)) !== null) {
    comments.push(match[1].trim());
  }
  return comments;
};

// --- Core Detection Logic ---

function checkPattern(
  patternDef: PatternDefinition,
  pageData: PageContentResult,
  scripts: {src: string[], content: string[]},
  cssLinks: string[],
  headers: Record<string, string | string[]>,
  metaTags: {name: Record<string, string>, property: Record<string, string>},
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

  const { html } = pageData; // Ensure html is directly available

  switch (patternDef.type) {
    case 'htmlContent':
      if (html && patternDef.pattern) testAndExtract(html, patternDef.pattern, patternDef.versionCaptureGroup);
      break;
    case 'scriptSrc':
      if (patternDef.pattern) scripts.src.forEach(s => testAndExtract(s, patternDef.pattern!, patternDef.versionCaptureGroup));
      break;
    case 'scriptContent':
      if (patternDef.pattern) scripts.content.forEach(s => testAndExtract(s, patternDef.pattern!, patternDef.versionCaptureGroup));
      break;
    case 'css': // Matches against CSS file URLs (can be expanded to inline CSS content if needed)
      if (patternDef.pattern) cssLinks.forEach(link => testAndExtract(link, patternDef.pattern!, patternDef.versionCaptureGroup));
      break;
    case 'header':
      const headerKey = patternDef.name?.toLowerCase();
      if (headerKey) {
        const headerVal = headers[headerKey];
        if (headerVal) {
          const headerValStr = Array.isArray(headerVal) ? headerVal.join(', ') : headerVal;
          if (patternDef.valuePattern) {
            testAndExtract(headerValStr, patternDef.valuePattern, patternDef.versionCaptureGroup);
          } else { // Header existence is enough if no valuePattern
            match = true;
            matchedValue = headerKey;
          }
        }
      }
      break;
    case 'metaName':
      const metaNameKey = patternDef.name?.toLowerCase();
      if (metaNameKey && metaTags.name[metaNameKey]) {
        if (patternDef.contentPattern) {
          testAndExtract(metaTags.name[metaNameKey], patternDef.contentPattern, patternDef.versionCaptureGroup);
        } else {
          match = true;
          matchedValue = metaNameKey;
        }
      }
      break;
    case 'metaProperty':
        const metaPropKey = patternDef.name?.toLowerCase(); // Using name for property key
        if (metaPropKey && metaTags.property[metaPropKey]) {
          if (patternDef.contentPattern) {
            testAndExtract(metaTags.property[metaPropKey], patternDef.contentPattern, patternDef.versionCaptureGroup);
          } else {
            match = true;
            matchedValue = metaPropKey;
          }
        }
        break;
    case 'cookie':
        cookies.forEach(cookie => {
            const nameToTest = cookie.name;
            // Match cookie name. If patternDef.name is a regex string, use it. Otherwise, patternDef.pattern is for the name.
            const namePattern = patternDef.name && typeof patternDef.pattern === 'string' // This logic needs review: patternDef.pattern should be RegExp
                                ? new RegExp(patternDef.name) // if name exists, pattern (which is string) becomes the regex
                                : patternDef.pattern;         // otherwise, pattern (which is RegExp) is for the name


            if (namePattern instanceof RegExp && namePattern.test(nameToTest)) {
                if (patternDef.valuePattern) { 
                    testAndExtract(cookie.value, patternDef.valuePattern, patternDef.versionCaptureGroup);
                } else {
                    match = true;
                    matchedValue = cookie.name;
                }
            } else if (typeof namePattern === 'string' && namePattern === nameToTest) { // Exact name match if patternDef.name is string and patternDef.pattern is undefined/not regex
                 if (patternDef.valuePattern) { 
                    testAndExtract(cookie.value, patternDef.valuePattern, patternDef.versionCaptureGroup);
                } else {
                    match = true;
                    matchedValue = cookie.name;
                }
            }
        });
        break;
    case 'jsGlobal':
      if (patternDef.pattern && jsGlobals.some(g => patternDef.pattern!.test(g))) {
        match = true;
        const matchedGlobal = jsGlobals.find(g => patternDef.pattern!.test(g));
        matchedValue = matchedGlobal;
      }
      break;
    case 'networkRequest':
      if (patternDef.pattern) networkRequests.forEach(req => testAndExtract(req, patternDef.pattern!, patternDef.versionCaptureGroup));
      break;
    case 'jsVersion':
      if (patternDef.versionProperty && jsVersions[patternDef.versionProperty]) {
        const verStr = jsVersions[patternDef.versionProperty];
        if (verStr && patternDef.pattern) { // Ensure pattern is defined
          testAndExtract(verStr, patternDef.pattern, patternDef.versionCaptureGroup || 1);
        }
      }
      break;
    case 'htmlComment':
      if (patternDef.pattern) htmlComments.forEach(comment => testAndExtract(comment, patternDef.pattern!, patternDef.versionCaptureGroup));
      break;
    case 'robots':
      if (robotsTxtContent && patternDef.pattern) {
        testAndExtract(robotsTxtContent, patternDef.pattern, patternDef.versionCaptureGroup);
      }
      break;
    case 'url':
        if (patternDef.pattern) testAndExtract(currentUrl, patternDef.pattern, patternDef.versionCaptureGroup);
        break;
    case 'domQuerySelector':
      // This is a simplified DOM check using regex on HTML source as true DOM parsing is not available here.
      // More robust solution would require jsdom or similar if running server-side.
      // For client-side, document.querySelector would be used.
      if (html && patternDef.selector) {
        // Create a regex that tries to find an element matching the selector approximately
        // This is highly heuristic and error-prone.
        // Example: selector '#myId' -> /<[^>]+id=["']myId["'][^>]*>/
        // Example: selector '.myClass' -> /<[^>]+class=["'][^"']*\bmyClass\b[^"']*["'][^>]*>/
        // Example: selector 'div[data-test="value"]' -> /<div[^>]+data-test=["']value["'][^>]*>/
        // This part needs significant improvement or a different approach for reliability.
        
        let domPatternString = patternDef.selector.replace(/([.#\[\]()])/g, '\\$1'); // Basic escape
        if (patternDef.selector.startsWith('#')) {
            domPatternString = `<[^>]+id=["']${patternDef.selector.substring(1)}["'][^>]*>`;
        } else if (patternDef.selector.startsWith('.')) {
            domPatternString = `<[^>]+class=["'][^"']*(?:^|\\s)${patternDef.selector.substring(1)}(?:\\s|$)["'][^>]*>`;
        } else if (patternDef.selector.includes('[')) {
             // Simplistic parsing for attribute selectors like tag[attr="value"]
            const attrMatch = patternDef.selector.match(/(\w+)?\[([\w-]+)(?:="([^"]+)")?\]/);
            if (attrMatch) {
                const tag = attrMatch[1] || '[^>\\s]+'; // Any tag if not specified
                const attr = attrMatch[2];
                const val = attrMatch[3] ? `=["']${attrMatch[3]}["']` : '';
                domPatternString = `<${tag}[^>]*${attr}${val}[^>]*>`;
            }
        } else {
            domPatternString = `<${patternDef.selector}[^>]*>`; // Match by tag name
        }

        try {
            const domRegex = new RegExp(domPatternString, 'i');
            const execResult = domRegex.exec(html);
            if (execResult) {
                match = true;
                matchedValue = execResult[0]; // The matched HTML tag
                // Further checks for attributeValuePattern or textContentPattern would require more complex regex on execResult[0]
                if (patternDef.attributeName && patternDef.attributeValuePattern) {
                    const attrValRegex = new RegExp(`${patternDef.attributeName}=["']([^"']*)["']`, 'i');
                    const attrValMatch = execResult[0].match(attrValRegex);
                    if (!attrValMatch || !patternDef.attributeValuePattern.test(attrValMatch[1])) {
                        match = false; // Attribute value doesn't match
                    }
                }
                 if (patternDef.textContentPattern) {
                    // Simplistic: check if patternDef.textContentPattern matches anything between > and < of the matched element
                    const innerContentRegex = />([^<]*)</;
                    const innerContentMatch = execResult[0].match(innerContentRegex);
                    if (!innerContentMatch || !patternDef.textContentPattern.test(innerContentMatch[1])) {
                        match = false; // Text content doesn't match
                    }
                }
            }
        } catch (e) {
            console.warn(`[Signatures] Invalid regex for DOM selector '${patternDef.selector}': ${domPatternString}`, e);
        }
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

  if (!pageData.html && (!pageData.headers || Object.keys(pageData.headers).length === 0)) {
    console.log("[Signatures] No HTML or headers to analyze.");
    return [];
  }
  const html = pageData.html || ""; // Use empty string if null for regex safety

  const headers = pageData.headers || {};
  const scripts = extractScripts(pageData); // {src: string[], content: string[]}
  const cssLinks = extractCssLinks(pageData);
  const metaTags = extractMetaTags(pageData); // {name: {}, property: {}}
  const cookies = extractCookies(pageData);
  const jsGlobals = extractPotentialJsGlobals(pageData);
  const networkRequests = extractNetworkRequests(pageData);
  const htmlComments = extractHtmlComments(pageData);
  const jsVersions = extractJsVersions(pageData);

  let robotsTxtContent: string | null = null;
  const hasRobotsPattern = Object.values(signatures).flat().some(sig =>
    (sig.additionalPatterns || []).some(p => p.type === 'robots') ||
    Object.values(sig.versions || {}).some(v => v.additionalPatterns.some(p => p.type === 'robots'))
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
      let overallConfidenceScore = 0; // Weighted average or max of pattern confidences
      let totalWeight = 0;
      let detectedVersion: string | null = null;
      let primaryMatchedValue: string | undefined;
      let primaryDetectionMethod: string | undefined;
      let matchOccurred = false;

      const processPatternsList = (patterns: PatternDefinition[] | undefined, baseConfidenceForSigOrVersion: number) => {
        if (!patterns) return;
        for (const pDef of patterns) {
          const result = checkPattern(pDef, pageData, scripts, cssLinks, headers, metaTags, cookies, jsGlobals, networkRequests, htmlComments, jsVersions, finalUrl, robotsTxtContent);
          if (result.match) {
            matchOccurred = true;
            const patternWeight = pDef.weight !== undefined ? pDef.weight : 0.5; // Default weight if pattern doesn't specify
            const currentPatternConfidence = baseConfidenceForSigOrVersion * patternWeight;

            // Use the highest confidence found for this technology so far
            if (currentPatternConfidence > overallConfidenceScore) {
                overallConfidenceScore = currentPatternConfidence;
                if (result.version) detectedVersion = result.version;
                if (result.matchedValue) primaryMatchedValue = result.matchedValue;
                primaryDetectionMethod = pDef.detectionMethod || `Type: ${pDef.type}, Pattern: ${pDef.pattern?.source.substring(0,30) || pDef.name || pDef.selector}`;
            } else if (currentPatternConfidence === overallConfidenceScore && result.version && !detectedVersion) {
                // If confidence is same, but this pattern found a version and we don't have one yet
                detectedVersion = result.version;
                 if (result.matchedValue) primaryMatchedValue = result.matchedValue; // Prioritize MV from versioned pattern
                primaryDetectionMethod = pDef.detectionMethod || `Type: ${pDef.type}, Pattern: ${pDef.pattern?.source.substring(0,30) || pDef.name || pDef.selector}`;
            }
          }
        }
      };
      
      // Process version-specific patterns first
      if (sigDef.versions) {
        for (const versionName in sigDef.versions) {
          // Skip if versionName is not a "version key" (e.g. if 'patterns' or 'versionProperty' was a key)
          if (typeof sigDef.versions[versionName] !== 'object' || !sigDef.versions[versionName].additionalPatterns) continue;

          const versionSigDetail = sigDef.versions[versionName];
          let versionSpecificMatchOccurred = false;
          let versionSpecificHighestConfidence = 0;
          let versionSpecificDetectedVersion : string | null = null; // Can be from pattern or versionName
          let versionSpecificMatchedValue: string | undefined;
          let versionSpecificDetectionMethod: string | undefined;

          for (const pDef of versionSigDetail.additionalPatterns) {
            const result = checkPattern(pDef, pageData, scripts, cssLinks, headers, metaTags, cookies, jsGlobals, networkRequests, htmlComments, jsVersions, finalUrl, robotsTxtContent);
            if (result.match) {
              versionSpecificMatchOccurred = true;
              const patternWeight = pDef.weight !== undefined ? pDef.weight : 0.6; // Default weight for version patterns
              // Confidence for this specific version pattern: version's base confidence * pattern's weight
              const currentPatternConfidence = (versionSigDetail.confidence || sigDef.confidence || 50) * patternWeight;

              if (currentPatternConfidence > versionSpecificHighestConfidence) {
                versionSpecificHighestConfidence = currentPatternConfidence;
                versionSpecificDetectedVersion = result.version || versionName; // Prefer pattern's version, fallback to key
                versionSpecificMatchedValue = result.matchedValue;
                versionSpecificDetectionMethod = pDef.detectionMethod || `Version '${versionName}', Type: ${pDef.type}, Pattern: ${pDef.pattern?.source.substring(0,30) || pDef.name || pDef.selector}`;
              }
            }
          }

          if (versionSpecificMatchOccurred && versionSpecificHighestConfidence > overallConfidenceScore) {
            matchOccurred = true; // A match for the technology happened via one of its versions
            overallConfidenceScore = versionSpecificHighestConfidence;
            detectedVersion = versionSpecificDetectedVersion;
            primaryMatchedValue = versionSpecificMatchedValue;
            primaryDetectionMethod = versionSpecificDetectionMethod;
          }
        }
      }
      
      // Process general patterns for the signature if defined in additionalPatterns
      // This will run if no versions matched, or if its confidence is higher
      // To ensure general patterns don't override a higher-confidence version match,
      // we only process them if their potential max confidence is higher OR if no version was found yet.
      const sigBaseConfidence = sigDef.confidence || 50; // Default confidence for the signature
      if (sigDef.additionalPatterns && (!matchOccurred || sigBaseConfidence > overallConfidenceScore) ) {
          processPatternsList(sigDef.additionalPatterns, sigBaseConfidence);
      }


      // Try jsVersionProperty from main signature def if no version found yet and property exists
      if (!detectedVersion && sigDef.js && typeof sigDef.js === 'object') {
         for (const jsGlobalProp in sigDef.js) {
            if (jsVersions[jsGlobalProp]) {
                const jsVal = sigDef.js[jsGlobalProp];
                let versionFromJs = jsVersions[jsGlobalProp];
                let confidenceFromJs = 50; // Default

                if (typeof jsVal === 'object' && jsVal.version && versionFromJs) {
                    // Extract version using regex from jsVal.version
                    try {
                        const versionRegex = new RegExp(jsVal.version.replace('\\\\1', '(\\S+)')); // Simple \\1 to capture group
                        const vMatch = versionFromJs.match(versionRegex);
                        if (vMatch && vMatch[1]) versionFromJs = vMatch[1];
                    } catch (e) { /* ignore regex error */ }
                }
                if (typeof jsVal === 'object' && jsVal.confidence) confidenceFromJs = jsVal.confidence;

                if (versionFromJs && confidenceFromJs > overallConfidenceScore) {
                    overallConfidenceScore = confidenceFromJs;
                    detectedVersion = versionFromJs;
                    matchOccurred = true;
                    primaryDetectionMethod = `JS Global Version: ${jsGlobalProp}`;
                    primaryMatchedValue = versionFromJs;
                } else if (versionFromJs && !detectedVersion) { // Take any version if none found yet
                     overallConfidenceScore = Math.max(overallConfidenceScore, confidenceFromJs); // Update confidence if higher
                     detectedVersion = versionFromJs;
                     matchOccurred = true;
                     primaryDetectionMethod = `JS Global Version: ${jsGlobalProp}`;
                     primaryMatchedValue = versionFromJs;
                }
            }
         }
      }


      if (matchOccurred && overallConfidenceScore > 10) { // Detection threshold (e.g., >10%)
        const finalConfidence = Math.min(100, Math.round(overallConfidenceScore)); // Cap at 100
        const existing = detectedTechMap.get(sigDef.name);
        if (!existing || finalConfidence > existing.confidence) {
          detectedTechMap.set(sigDef.name, {
            technology: sigDef.name,
            version: detectedVersion,
            confidence: finalConfidence,
            category: categoryName, // Main category
            categories: sigDef.categories || [categoryName], // All associated categories
            website: sigDef.website,
            icon: sigDef.icon,
            matchedValue: primaryMatchedValue,
            detectionMethod: primaryDetectionMethod,
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
    const meta = tech._meta;
    if (!meta) return true;

    if (meta.requires) {
      if (!meta.requires.every(req => {
        const reqName = typeof req === 'string' ? req : req.name;
        return detectedTechMap.has(reqName);
      })) {
        return false; 
      }
    }
    if (meta.requiresCategory) {
      if (!meta.requiresCategory.some(reqCat =>
        finalDetections.some(d => (d.categories?.includes(reqCat) || d.category === reqCat) && d.technology !== tech.technology)
      )) {
        return false; 
      }
    }
    return true;
  });
  detectedTechMap = new Map(finalDetections.map(t => [t.technology, t]));


  // 2. Apply 'excludes'
  const excludedTechNames = new Set<string>();
  for (const tech of finalDetections) {
    const meta = tech._meta;
    if (meta?.excludes) {
      meta.excludes.forEach(ex => {
        const exName = typeof ex === 'string' ? ex : ex.name;
        if (detectedTechMap.has(exName)) {
          excludedTechNames.add(exName);
        }
      });
    }
  }
  finalDetections = finalDetections.filter(tech => !excludedTechNames.has(tech.technology));
  detectedTechMap = new Map(finalDetections.map(t => [t.technology, t]));


  // 3. Apply 'implies'
  const impliedDetectionsToAdd: DetectedTechnologyInfo[] = [];
  let newImpliesMade;
  do {
    newImpliesMade = false;
    for (const tech of Array.from(detectedTechMap.values())) { // Iterate over current state of map
        const meta = tech._meta;
        if (meta?.implies) {
            meta.implies.forEach(impliedItem => {
                const impliedName = typeof impliedItem === 'string' ? impliedItem : impliedItem.name;
                const impliedConfidenceOverride = typeof impliedItem !== 'string' ? impliedItem.confidence : undefined;

                if (!detectedTechMap.has(impliedName)) {
                    let impliedSigDef: SignatureDefinition | undefined;
                    let impliedCategory: string | undefined;
                    for (const cat in signatures) {
                        impliedSigDef = signatures[cat].find(s => s.name === impliedName);
                        if (impliedSigDef) {
                            impliedCategory = cat;
                            break;
                        }
                    }
                    if (impliedSigDef) {
                        const impliedBaseConfidence = impliedSigDef.confidence || 30; // Default for implied
                        const implicationConfidence = impliedConfidenceOverride !== undefined ? impliedConfidenceOverride : (tech.confidence * 0.5); // 50% of implier's confidence
                        const finalImpliedConfidence = Math.min(100, Math.round(Math.max(impliedBaseConfidence, implicationConfidence)));
                        
                        const newImpliedTech: DetectedTechnologyInfo = {
                            technology: impliedName,
                            version: null, 
                            confidence: finalImpliedConfidence,
                            category: impliedCategory,
                            categories: impliedSigDef.categories || (impliedCategory ? [impliedCategory] : []),
                            website: impliedSigDef.website,
                            icon: impliedSigDef.icon,
                            detectionMethod: `Implied by ${tech.technology}`,
                            _meta: { // Carry over _meta from implied tech for further processing
                                implies: impliedSigDef.implies, 
                                excludes: impliedSigDef.excludes, 
                                requires: impliedSigDef.requires, 
                                requiresCategory: impliedSigDef.requiresCategory 
                            }
                        };
                        impliedDetectionsToAdd.push(newImpliedTech);
                        detectedTechMap.set(impliedName, newImpliedTech); // Add to map immediately to allow chained implies
                        newImpliesMade = true; 
                    }
                }
            });
        }
    }
  } while (newImpliesMade); // Loop if new implies were made, as they might trigger more implies


  // Merge original finalDetections with newly added implied ones, avoiding duplicates from map
  finalDetections = Array.from(detectedTechMap.values());


  // Clean up _meta field from final output
  return finalDetections.map(tech => {
    const { _meta, ...rest } = tech;
    return rest as DetectedTechnologyInfo; // Cast to ensure type correctness
  });
}
