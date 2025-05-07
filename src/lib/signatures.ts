
// src/lib/signatures.ts

// Categories (inspired by Wappalyzer's cats.json, simplified)
// We can expand this later with actual IDs and names from Wappalyzer if needed.
const CATEGORIES: Record<string, string> = {
  '1': 'CMS',
  '2': 'Message Boards',
  '3': 'Database Managers',
  '4': 'Documentation Tools',
  '5': 'Widgets',
  '6': 'Web Frameworks',
  // ... add more as needed
  '10': 'Analytics', // Wappalyzer uses 10 for Analytics
  '11': 'JavaScript Libraries',
  '12': 'Photo Galleries',
  '13': 'Wikis',
  '14': 'Hosting Panels',
  // '15': 'Analytics', // Duplicate from 10, using 10
  '18': 'Operating Systems',
  '19': 'Search Engines',
  '22': 'Web Servers',
  '23': 'Advertising', // For Ad Networks
  '25': 'Cache Tools',
  '26': 'Rich Text Editors',
  '27': 'JavaScript Frameworks', // Differentiated from Libraries
  '28': 'Maps',
  '29': 'Advertising Networks', // Also 23, consolidating if possible
  '30': 'Network Devices',
  '31': 'Media Servers',
  '32': 'Webmail',
  '34': 'Payment Processors',
  '36': 'CDN',
  '40': 'Web Services', // Generic for things like Open Graph if not more specific
  '42': 'Marketing Automation', // For OneTrust if it fits
  '47': 'UI Frameworks', // Good for Emotion
  '57': 'Programming Languages',
  '59': 'Database',
  '62': 'Security', // For HSTS
  '65': 'Font Scripts',
  '66': 'Reverse Proxies', // For Envoy
  '68': 'Cookie Compliance', // For OneTrust
  '69': 'Miscellaneous', // For OpenGraph or general fallbacks
  '70': 'Distributed Tracing', // For Zipkin
};

// Represents a detailed check within a DOM element
export interface DomCheck {
  exists?: string; // Empty string means just check existence, otherwise a pattern for the element itself
  text?: string; // Regex for text content
  attributes?: Record<string, string>; // attrName: regex value pattern
  properties?: Record<string, string>; // propName: regex value pattern (harder with regex, for future expansion)
}


export interface TechnologySignature {
  // Wappalyzer core fields
  name: string; // Name of the technology (used as key in Wappalyzer's JSON)
  cats?: number[]; // Category IDs
  description?: string;
  website: string;
  icon?: string; // e.g., "React.svg"
  cpe?: string; // Common Platform Enumeration
  saas?: boolean;
  oss?: boolean;
  pricing?: string[]; // e.g., ["low", "freemium"]

  // Detection patterns
  cookies?: Record<string, string>; // name: regex value pattern
  // dom can be a string (selector), array of strings (selectors), or object (selector -> DomCheck)
  dom?: string | string[] | Record<string, DomCheck | string>;
  dns?: Record<string, string[]>; // e.g., { "MX": ["example\\.com"] } (for future use)
  headers?: Record<string, string>; // headerName: regex value pattern
  html?: string | string[]; // regex patterns for raw HTML
  text?: string | string[]; // regex patterns for text content (HTML stripped)
  js?: Record<string, string>; // JS variable/property paths: regex value pattern or empty for existence
  meta?: Record<string, string>; // metaTagName: regex content pattern
  scriptSrc?: string | string[]; // regex for <script src="..." URLs
  scripts?: string | string[]; // regex for inline <script> content or external script content (if fetched)
  url?: string | string[]; // regex for the page URL
  robots?: string | string[]; // regex for robots.txt content (for future use)
  probe?: Record<string, string>; // path: regex for content at path (for future use)
  xhr?: string | string[]; // regex for XHR/fetch request URLs (for future use)
  css?: string | string[]; // regex for CSS rules (applied to inline styles or fetched CSS)

  // Relationships
  implies?: string | string[]; // Tech names or "TechName\\;confidence:XX"
  requires?: string | string[];
  requiresCategory?: number[];
  excludes?: string | string[];

  // Fields used by our system, can be derived or explicit
  id: string; // Unique ID for the signature (can be same as name or more specific)
  confidence?: number; // Base confidence for this specific signature rule if not in pattern (0.0-1.0)
  version?: string; // Static version if pattern doesn't extract it
  // detectionMethod?: string; // Auto-generated based on type
  category?: string; // Human-readable category from CATEGORIES
}

export interface DetectedTechnologyInfo {
  id: string;
  name: string;
  version?: string;
  confidence: number; // Overall confidence after considering pattern tags and base confidence
  category: string;
  detectionMethod: string;
  matchedValue?: string;
  website?: string;
  icon?: string;
}

interface ParsedPattern {
  regex: RegExp;
  confidence?: number; // 0-100 from pattern tag
  version?: string; // Version template like \1 or \1?value:other
}

// Helper to parse patterns like "jquery-([0-9.]+)\\.js\\;version:\\1\\;confidence:50"
function parseTaggedPattern(patternStr: string): ParsedPattern {
  const parts = patternStr.split('\\;');
  const regexStr = parts[0];
  let confidence: number | undefined;
  let version: string | undefined;

  for (let i = 1; i < parts.length; i++) {
    const tag = parts[i];
    if (tag.startsWith('confidence:')) {
      confidence = parseInt(tag.substring('confidence:'.length), 10);
    } else if (tag.startsWith('version:')) {
      version = tag.substring('version:'.length);
    }
  }
  // Wappalyzer treats regex as case-insensitive by default
  return { regex: new RegExp(regexStr, 'i'), confidence, version };
}

function applyVersionTemplate(match: RegExpExecArray, template?: string): string | undefined {
    if (!template || !match) return undefined;

    const ternaryMatch = template.match(/^\\(\d)\?(.*?)(?::(.*?))?$/);
    if (ternaryMatch) {
        const groupIndex = parseInt(ternaryMatch[1], 10);
        const trueVal = ternaryMatch[2];
        const falseVal = ternaryMatch[3];
        if (match[groupIndex]) {
            return trueVal.replace(/\\(\d)/g, (_m, gi) => match[parseInt(gi, 10)] || '');
        } else if (falseVal !== undefined) {
            return falseVal.replace(/\\(\d)/g, (_m, gi) => match[parseInt(gi, 10)] || '');
        }
        return undefined;
    }

    return template.replace(/\\(\d)/g, (_m, groupIndexStr) => {
        const groupIndex = parseInt(groupIndexStr, 10);
        return match[groupIndex] || '';
    }).trim() || undefined;
}


// --- Extraction Utilities ---

function extractScriptSrcs(html: string): string[] {
  const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
  const srcs: string[] = [];
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    srcs.push(match[1]);
  }
  return srcs;
}

function extractLinkHrefs(html: string, rel?: string): string[] {
  const relPattern = rel ? `\\srel=["'](?:[^"']*\s)?${rel}(?:\\s[^"']*)?["']` : "";
  const linkRegex = new RegExp(`<link[^>]+href=["']([^"']+)["']${relPattern}[^>]*>`, 'gi');
  const hrefs: string[] = [];
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    hrefs.push(match[1]);
  }
  return hrefs;
}

function extractMetaTags(html: string): Record<string, string[]> {
  const metaStore: Record<string, string[]> = {};
  const metaRegex = /<meta[^>]+(?:name|property)=["']([^"':\s]+)["'][^>]*content=["']([^"']*)["']/gi;
  let match;
  while ((match = metaRegex.exec(html)) !== null) {
    const key = match[1].toLowerCase();
    const content = match[2];
    if (!metaStore[key]) {
      metaStore[key] = [];
    }
    metaStore[key].push(content);
  }
  return metaStore;
}

function extractInlineScriptContents(html: string): string[] {
  const scriptContentRegex = /<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi;
  const contents: string[] = [];
  let match;
  while((match = scriptContentRegex.exec(html)) !== null) {
    if (match[1].trim()) {
      contents.push(match[1]);
    }
  }
  return contents;
}

function extractTextContent(html: string): string {
  let text = html.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');
  text = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
  text = text.replace(/<!--[\s\S]*?-->/gi, '');
  text = text.replace(/<[^>]+>/g, ' ');
  return text.replace(/\s+/g, ' ').trim();
}

function extractDocumentCookies(cookieString?: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieString) return cookies;
  cookieString.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const name = parts.shift()?.trim();
    const value = parts.join('=');
    if (name) {
      cookies[name] = value;
    }
  });
  return cookies;
}

function extractInlineStyles(html: string): string {
    const styleRegex = /<style[^>]*>([\s\S]*?)<\/style>/gi;
    let styles = "";
    let match;
    while((match = styleRegex.exec(html)) !== null) {
        styles += match[1] + "\n";
    }
    return styles.trim();
}


// --- Signatures Database (Examples) ---
export const signaturesDb: TechnologySignature[] = [
  {
    id: 'React', name: 'React', cats: [27], website: 'https://reactjs.org/', icon: 'React.svg',
    js: {
      'React.version': '([\\d.]+)\\;version:\\1', // Wappalyzer style
      '__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size': '.+'
    },
    dom: { // Wappalyzer style
        '[data-reactroot]': {exists: ""},
        '[data-reactid]': {exists: ""}
    },
    implies: "ReactDOM",
    description: "React is a JavaScript library for building user interfaces."
  },
  {
    id: 'ReactDOM', name: 'ReactDOM', cats: [27], website: 'https://reactjs.org/', icon: 'React.svg',
    scriptSrc: "react-dom(?:[-.]([\\d.]+))?(?:\\.min)?\\.js\\;version:\\1",
    description: "ReactDOM is the entry point of the DOM-related rendering paths for React."
  },
  {
    id: 'Next.js', name: 'Next.js', cats: [6, 27], website: 'https://nextjs.org/', icon: 'Next.js.svg',
    headers: { 'X-Powered-By': '^Next\\.js(?: ([\\d.]+))?\\;version:\\1' },
    dom: { '#__NEXT_DATA__': { exists: "" } }, // Wappalyzer style for <script id="__NEXT_DATA__">
    js: { 'next.version': '(.+)\\;version:\\1' },
    implies: 'React',
    description: "Next.js is a React framework for production."
  },
  {
    id: 'jQuery', name: 'jQuery', cats: [11], website: 'https://jquery.com/', icon: 'jQuery.svg',
    scriptSrc: [
        "jquery(?:-([\\d.]*[\\d]))?(?:\\.min|\\.slim|\\.slim\\.min)?\\.js\\;version:\\1",
        "ajax.googleapis.com/ajax/libs/jquery/([\\d.]+)/jquery.min.js\\;version:\\1"
    ],
    js: { 'jQuery.fn.jquery': '([\\d.]+)\\;version:\\1' }, // Wappalyzer style
    description: "jQuery is a fast, small, and feature-rich JavaScript library."
  },
  {
    id: 'Google Analytics', name: 'Google Analytics', cats: [10], website: 'https://analytics.google.com/', icon: 'Google Analytics.svg',
    scriptSrc: [
      "googletagmanager\\.com/gtag/js\\?id=(UA-[\\d-]+(?:-\\d+)?|G-[A-Z0-9]+)", // Supports both UA and G
      "google-analytics\\.com/(?:ga|urchin|analytics)\\.js"
    ],
    js: { // Wappalyzer often checks for existence or specific values
      'ga': '', 'gaplugins': '', '_gaq': '', 'GoogleAnalyticsObject': '',
      'dataLayer.push': '\\Wconfig\\W.*(UA-|G-)' // Checks if dataLayer.push configures GA
    },
    cookies: { '_ga': '', '_gid': '', '_gat': '' },
    description: "Google Analytics is a web analytics service that tracks and reports website traffic."
  },
  {
    id: 'WordPress', name: 'WordPress', cats: [1], website: 'https://wordpress.org/', icon: 'WordPress.svg',
    meta: { 'generator': 'WordPress ([\\d.]+)\\;version:\\1' },
    html: [
        "<link rel=[\"']stylesheet[\"'] [^>]+wp-content",
        "<link rel=[\"']stylesheet[\"'] [^>]+wp-includes"
    ],
    scriptSrc: ["/wp-includes/", "/wp-content/"],
    dom: { // Example of more specific DOM checks
        'body.wp-admin': { exists: ""}, // If on an admin page
        '#wpadminbar': { exists: ""},
        'link[href*="wp-content/themes"]': {exists: ""} // Check for theme CSS
    },
    implies: 'PHP',
    description: "WordPress is a free and open-source content management system."
  },
  {
    id: 'PHP', name: 'PHP', cats: [57], website: 'https://php.net', icon: 'PHP.svg',
    headers: {
      'X-Powered-By': 'PHP(?:/([\\d.]+))?\\;version:\\1',
      'Set-Cookie': 'PHPSESSID' // Common PHP session cookie
    },
    url: '\\.php(?:$|\\?)',
    description: "PHP is a popular general-purpose scripting language that is especially suited to web development."
  },
  {
    id: 'Cloudflare', name: 'Cloudflare', cats: [36, 62], website: 'https://www.cloudflare.com/', icon: 'Cloudflare.svg',
    headers: { 'Server': 'cloudflare', 'cf-ray': '.+', 'CF-RAY': '.+' }, // CF-RAY can be uppercase
    cookies: { '__cf_bm': '.+', '__cfduid': '.+', 'cf_clearance': '.+' },
    js: { 'Cloudflare': '' , 'window.Cloudflare': ''},
    scriptSrc: "cdn-cgi/challenge-platform", // For bot protection pages
    description: "Cloudflare is a CDN, DNS, DDoS protection, and security service."
  },
  {
    id: 'Zipkin', name: 'Zipkin', cats: [70], website: 'https://zipkin.io/', icon: 'Zipkin.svg',
    headers: {
      'X-B3-TraceId': '.+',
      'X-B3-SpanId': '.+'
    },
    description: "Zipkin is a distributed tracing system."
  },
  {
    id: 'Emotion', name: 'Emotion', cats: [47], website: 'https://emotion.sh/', icon: 'Emotion.png',
    html: '<style[^>]+data-emotion(?:-css)?=',
    js: { 'caches.inserted': '' },
    css: ["\\.css-[a-zA-Z0-9]+", "data-emotion"], // Look for generated class names or data-emotion in styles
    description: "Emotion is a library designed for writing CSS styles with JavaScript."
  },
  {
    id: 'HSTS', name: 'HSTS', cats: [62], website: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security', icon: 'HSTS.svg',
    headers: { 'Strict-Transport-Security': '.+' },
    description: "HTTP Strict Transport Security (HSTS) is a web security policy mechanism."
  },
  {
    id: 'Open Graph', name: 'Open Graph', cats: [40, 69], website: 'https://ogp.me/', icon: 'OpenGraph.svg',
    meta: {
      'og:title': '.+',
      'og:type': '.+',
      'og:url': '.+',
      'og:image': '.+'
    },
    html: '<html[^>]+prefix="og:',
    description: "The Open Graph protocol enables any web page to become a rich object in a social graph."
  },
  {
    id: 'BitPay', name: 'BitPay', cats: [34], website: 'https://bitpay.com/', icon: 'BitPay.svg',
    scriptSrc: 'bitpay\\.com/bitpay\\.js',
    dom: { 'iframe#bitpay': { exists: ""} },
    js: { 'bitpay': '' },
    description: "BitPay provides Bitcoin and crypto payment processing services."
  },
  {
    id: 'Lodash', name: 'Lodash', cats: [11], website: 'https://lodash.com/', icon: 'Lodash.svg',
    scriptSrc: 'lodash(?:\\.min)?\\.js.*(?:version=([\\d\\.]+))?\\;version:\\1',
    js: { '_.VERSION': '([\\d\\.]+)\\;version:\\1' },
    html: '<!-- Lodash ([\\d\\.]+) -->\\;version:\\1',
    description: "Lodash is a modern JavaScript utility library delivering modularity, performance, & extras."
  },
  {
    id: 'Envoy', name: 'Envoy', cats: [66, 22], website: 'https://www.envoyproxy.io/', icon: 'Envoy.svg',
    headers: {
      'server': '(?:envoy|Envoy)',
      'x-envoy-upstream-service-time': '.+'
    },
    description: "Envoy is an open source edge and service proxy, designed for cloud-native applications."
  },
  {
    id: 'OneTrust', name: 'OneTrust', cats: [68, 42], website: 'https://www.onetrust.com/', icon: 'OneTrust.svg',
    scriptSrc: ['cdn\\.cookielaw\\.org', 'optanon\\.blob\\.core\\.windows\\.net', 'geolocation\\.onetrust\\.com'],
    cookies: { 'OptanonConsent': '.+', 'OptanonAlertBoxClosed': '.+' },
    dom: { '#onetrust-banner-sdk': { exists: ""}, '#onetrust-consent-sdk': { exists: ""}},
    js: { 'Optanon': '' , 'OneTrust': ''},
    description: "OneTrust is a privacy, security, and data governance software provider."
  },
  {
    id: 'Netflix App', name: 'Netflix App', cats: [31], website: 'https://www.netflix.com', icon: 'Netflix.svg',
    url: 'netflix\\.com',
    js: {'netflix.reactContext':'', 'netflix.falcor':''},
    dom: {'[data-uia="player"]': {exists: ""}, 'body.netflix-sans': {exists: ""}},
    meta: {'twitter:app:name:iphone': 'Netflix'},
    description: "Netflix is a streaming service for TV shows and movies."
  }
];

// --- Main Detection Function ---
export interface DetectionInput {
  url: string;
  htmlContent: string;
  headers?: Record<string, string | string[]>; // From server response
  cookies?: string; // From document.cookie or Set-Cookie headers
  robotsTxtContent?: string; // Content of /robots.txt (for future use)
  // Potential future inputs: fetched CSS content, fetched JS content for deeper analysis
}

export function detectWithSignatures(input: DetectionInput): DetectedTechnologyInfo[] {
  const detectedStore = new Map<string, DetectedTechnologyInfo>();
  const { url, htmlContent, headers = {}, cookies: cookieString } = input;

  if (!htmlContent && !Object.keys(headers).length && !cookieString) {
    console.warn("[Signatures] No content (HTML, headers, cookies) provided for detection.");
    return [];
  }

  const scriptSrcs = htmlContent ? extractScriptSrcs(htmlContent) : [];
  const linkHrefsStylesheet = htmlContent ? extractLinkHrefs(htmlContent, "stylesheet") : [];
  const metaTags = htmlContent ? extractMetaTags(htmlContent) : {};
  const inlineScriptContents = htmlContent ? extractInlineScriptContents(htmlContent) : [];
  const plainTextContent = htmlContent ? extractTextContent(htmlContent) : "";
  const documentCookies = extractDocumentCookies(cookieString);
  const inlineStyles = htmlContent ? extractInlineStyles(htmlContent) : "";


  const processPattern = (
    valueToTest: string | undefined,
    patternStr: string,
    baseSigConfidence: number,
    sig: TechnologySignature,
    detectionMethodType: string,
    matchedDataSource: string
  ): DetectedTechnologyInfo | null => {
    if (valueToTest === undefined || valueToTest === null) return null;

    const parsed = parseTaggedPattern(patternStr);
    const match = parsed.regex.exec(valueToTest);

    if (match) {
      const versionFromPattern = applyVersionTemplate(match, parsed.version);
      const confidenceFromTag = parsed.confidence !== undefined ? parsed.confidence / 100 : baseSigConfidence;

      return {
        id: sig.id,
        name: sig.name,
        version: versionFromPattern || sig.version,
        confidence: Math.min(1.0, Math.max(0, confidenceFromTag)),
        category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
        detectionMethod: `${detectionMethodType}: ${sig.name} (on ${matchedDataSource})`,
        matchedValue: match[0].length > 200 ? match[0].substring(0, 197) + '...' : match[0],
        website: sig.website,
        icon: sig.icon,
      };
    }
    return null;
  };

  const addOrUpdateDetection = (techInfo: DetectedTechnologyInfo | null) => {
    if (!techInfo) return;
    const existing = detectedStore.get(techInfo.name);
    if (!existing || techInfo.confidence > existing.confidence || (techInfo.confidence === existing.confidence && techInfo.version && !existing.version)) {
      detectedStore.set(techInfo.name, techInfo);
    } else if (existing && techInfo.confidence === existing.confidence && techInfo.version && existing.version && techInfo.version !== existing.version) {
      // If confidences are same, but versions differ, take the longer version string or the new one if old one was generic
       if (techInfo.version.length > existing.version.length || (existing.version.includes("*") && !techInfo.version.includes("*"))) {
          detectedStore.set(techInfo.name, techInfo);
       }
    }
  };

  signaturesDb.forEach(sig => {
    const baseSigConfidence = sig.confidence ?? 1.0;

    // URL
    if (sig.url && url) {
      (Array.isArray(sig.url) ? sig.url : [sig.url]).forEach(p => {
        addOrUpdateDetection(processPattern(url, p, baseSigConfidence, sig, 'URL', 'page URL'));
      });
    }

    // Headers
    if (sig.headers && headers) {
      for (const headerName in sig.headers) {
        const headerPattern = sig.headers[headerName];
        const headerValueFromServer = headers[headerName.toLowerCase()] || headers[headerName];
        if (headerValueFromServer) {
          (Array.isArray(headerValueFromServer) ? headerValueFromServer : [headerValueFromServer]).forEach(val => {
            addOrUpdateDetection(processPattern(val, headerPattern, baseSigConfidence, sig, 'Header', headerName));
          });
        }
      }
    }

    // Cookies
    if (sig.cookies) {
      for (const cookieName in sig.cookies) {
        const cookiePattern = sig.cookies[cookieName]; // This is the regex for the cookie *value*
        if (documentCookies[cookieName]) { // Check if cookie with this name exists
          if (cookiePattern === "") { // Wappalyzer: empty string means check for existence
             addOrUpdateDetection({
                id: sig.id, name: sig.name, version: sig.version, confidence: baseSigConfidence,
                category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
                detectionMethod: `Cookie Exists: ${sig.name} (on ${cookieName})`,
                matchedValue: cookieName, website: sig.website, icon: sig.icon,
             });
          } else {
             addOrUpdateDetection(processPattern(documentCookies[cookieName], cookiePattern, baseSigConfidence, sig, 'Cookie Value', cookieName));
          }
        }
      }
    }
    
    if (htmlContent) {
        // Meta Tags
        if (sig.meta) {
          for (const metaNameKey in sig.meta) {
            const metaPattern = sig.meta[metaNameKey];
            if (metaTags[metaNameKey.toLowerCase()]) {
              metaTags[metaNameKey.toLowerCase()].forEach(content => {
                addOrUpdateDetection(processPattern(content, metaPattern, baseSigConfidence, sig, 'Meta Tag', metaNameKey));
              });
            }
          }
        }

        // scriptSrc
        if (sig.scriptSrc) {
          const sources = [...scriptSrcs, ...linkHrefsStylesheet];
          (Array.isArray(sig.scriptSrc) ? sig.scriptSrc : [sig.scriptSrc]).forEach(p => {
            sources.forEach(src => {
              addOrUpdateDetection(processPattern(src, p, baseSigConfidence, sig, 'Script/Link Src', 'script/link tag'));
            });
          });
        }

        // scripts (inline script content)
        if (sig.scripts) {
          (Array.isArray(sig.scripts) ? sig.scripts : [sig.scripts]).forEach(p => {
            inlineScriptContents.forEach(scriptContent => {
              addOrUpdateDetection(processPattern(scriptContent, p, baseSigConfidence, sig, 'Inline Script', 'script content'));
            });
          });
        }

        // html (raw html content)
        if (sig.html) {
          (Array.isArray(sig.html) ? sig.html : [sig.html]).forEach(p => {
            addOrUpdateDetection(processPattern(htmlContent, p, baseSigConfidence, sig, 'HTML Content', 'raw HTML'));
          });
        }
        
        // text (plain text content)
        if (sig.text) {
          (Array.isArray(sig.text) ? sig.text : [sig.text]).forEach(p => {
            addOrUpdateDetection(processPattern(plainTextContent, p, baseSigConfidence, sig, 'Text Content', 'page text'));
          });
        }

        // js (global vars / properties in inline scripts)
        // This is a simplified check on inline scripts. True JS execution is needed for full accuracy.
        if (sig.js) {
          for (const jsPath in sig.js) {
            const jsValuePatternStr = sig.js[jsPath]; // Regex for the value, or empty for existence check
            // Escape special characters in jsPath for regex creation
            const escapedPath = jsPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            // Regex to find `path = value` or `path: value` or just `path`
            // It tries to capture the value after '=' or ':'
            // Group 1: path, Group 2: (optional) value
            const jsPresencePattern = new RegExp(`(?:[\\s\\{\\(,;]|^)${escapedPath}(?:\\s*[=:]\\s*(['"\`]?((?:.|\\n)*?)['"\`]?))?`, 'gim');
            
            inlineScriptContents.forEach(scriptContent => {
              let match;
              while((match = jsPresencePattern.exec(scriptContent)) !== null) {
                const matchedJsValue = match[2] !== undefined ? match[2] : ""; // If no value captured, treat as empty string

                if (jsValuePatternStr === "" && match[0]) { // Existence check passed
                  addOrUpdateDetection({
                    id: sig.id, name: sig.name, version: sig.version, confidence: baseSigConfidence,
                    category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
                    detectionMethod: `JS Var Exists: ${sig.name} (on ${jsPath})`,
                    matchedValue: jsPath, website: sig.website, icon: sig.icon,
                  });
                } else if (jsValuePatternStr !== "") {
                  const parsedValuePattern = parseTaggedPattern(jsValuePatternStr);
                  const valueMatch = parsedValuePattern.regex.exec(matchedJsValue);
                  if (valueMatch) {
                    const versionFromJs = applyVersionTemplate(valueMatch, parsedValuePattern.version);
                    const confidenceFromTag = parsedValuePattern.confidence !== undefined ? parsedValuePattern.confidence / 100 : baseSigConfidence;
                    addOrUpdateDetection({
                      id: sig.id, name: sig.name,
                      version: versionFromJs || sig.version,
                      confidence: Math.min(1.0, confidenceFromTag),
                      category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
                      detectionMethod: `JS Var/Prop Value: ${sig.name} (on ${jsPath})`,
                      matchedValue: valueMatch[0].substring(0,100), website: sig.website, icon: sig.icon,
                    });
                  }
                }
              }
            });
          }
        }

        // DOM checks (regex based approximations)
        if (sig.dom) {
            const domPatterns = typeof sig.dom === 'string' ? { [sig.dom]: { exists: "" } } :
                                Array.isArray(sig.dom) ? sig.dom.reduce((acc, item) => { acc[item] = { exists: "" }; return acc; }, {} as Record<string, DomCheck>) :
                                sig.dom;

            for (const selector in domPatterns) {
                const check = typeof domPatterns[selector] === 'string' ? {exists: domPatterns[selector] as string} : domPatterns[selector] as DomCheck;
                
                // Try to build a regex for the selector. This is very simplified.
                // Handles basic ID (#id), class (.class), attribute ([attr=val], [attr]), and tag (tagname)
                let elementRegexStr = "";
                if (selector.startsWith('#')) { // ID
                    elementRegexStr = `<[^>\\s]+\\s[^>]*id=["']${selector.substring(1)}["'][^>]*>`;
                } else if (selector.startsWith('.')) { // Class
                    elementRegexStr = `<[^>\\s]+\\s[^>]*class=["'](?:[^"']+\\s)?${selector.substring(1)}(?:\\s[^"']*)?["'][^>]*>`;
                } else if (selector.startsWith('[')) { // Attribute
                     const attrMatch = selector.match(/^\[([^=\]]+)(?:=(["']?)([^\]"']+)\2)?\]$/);
                     if (attrMatch) {
                        elementRegexStr = `<[^>\\s]+\\s[^>]*${attrMatch[1]}`;
                        if (attrMatch[3]) { // attribute has value
                            elementRegexStr += `=["']${attrMatch[3]}["']`;
                        }
                        elementRegexStr += `[^>]*>`;
                     } else {
                        elementRegexStr = `<[^>\\s]+\\s[^>]*${selector.substring(1, selector.length -1 )}[^>]*>`
                     }
                } else if (selector.match(/^[a-zA-Z0-9-]+$/)) { // Tag name
                    elementRegexStr = `<${selector}(?:\\s[^>]*)?>`;
                } else { // Default to treating selector as part of content if complex
                    elementRegexStr = selector; 
                }


                const elementRegex = new RegExp(elementRegexStr, 'is'); // 's' for dotall, 'i' for case-insensitive
                let elementMatch = elementRegex.exec(htmlContent);

                if (elementMatch) { // Element potentially found
                    const matchedElementHtml = elementMatch[0];
                    
                    if (check.exists !== undefined) { // "exists" check
                         addOrUpdateDetection({
                            id: sig.id, name: sig.name, version: sig.version, confidence: baseSigConfidence,
                            category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
                            detectionMethod: `DOM Exists: ${sig.name} (selector: ${selector})`,
                            matchedValue: selector, website: sig.website, icon: sig.icon,
                         });
                    }

                    if (check.text) {
                        // Simplified text extraction from the matched element snippet
                        const textContentMatch = matchedElementHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
                        addOrUpdateDetection(processPattern(textContentMatch, check.text, baseSigConfidence, sig, 'DOM Text', `${selector} text`));
                    }

                    if (check.attributes) {
                        for (const attrName in check.attributes) {
                            const attrPattern = check.attributes[attrName];
                            // Regex to find attribute in the element snippet
                            const attrValueRegex = new RegExp(`${attrName}=["']([^"']*)["']`, 'i');
                            const attrMatchInElement = attrValueRegex.exec(matchedElementHtml);

                            if (attrMatchInElement) { // Attribute name found
                                if (attrPattern === "") { // Check for attribute existence
                                     addOrUpdateDetection({
                                        id: sig.id, name: sig.name, version: sig.version, confidence: baseSigConfidence,
                                        category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
                                        detectionMethod: `DOM Attr Exists: ${sig.name} (on ${selector} for attribute ${attrName})`,
                                        matchedValue: attrName, website: sig.website, icon: sig.icon,
                                     });
                                } else { // Check for attribute value pattern
                                   addOrUpdateDetection(processPattern(attrMatchInElement[1], attrPattern, baseSigConfidence, sig, 'DOM Attribute', `${selector} @${attrName}`));
                                }
                            }
                        }
                    }
                }
            }
        }
        // CSS checks (on inline styles)
        if (sig.css && inlineStyles) {
            (Array.isArray(sig.css) ? sig.css : [sig.css]).forEach(p => {
                addOrUpdateDetection(processPattern(inlineStyles, p, baseSigConfidence, sig, 'CSS Rule', 'inline styles'));
            });
        }
    } // End if(htmlContent)
  });


  const finalDetectionsList = Array.from(detectedStore.values());
  const finalDetectionMap = new Map<string, DetectedTechnologyInfo>(finalDetectionsList.map(d => [d.name, d]));

  // --- Post-processing: implies, requires, excludes (Simplified loop) ---
  let changedInPass;
  do {
    changedInPass = false;
    const currentTechNames = Array.from(finalDetectionMap.keys());

    for (const techName of currentTechNames) {
      const detectedTech = finalDetectionMap.get(techName);
      if (!detectedTech) continue; 
      const sig = signaturesDb.find(s => s.name === techName);
      if (!sig) continue;

      // Implications
      if (sig.implies) {
        const impliedTechs = Array.isArray(sig.implies) ? sig.implies : [sig.implies];
        impliedTechs.forEach(impliedStr => {
          const parts = impliedStr.split('\\;');
          const impliedName = parts[0];
          let impliedConfidence = detectedTech.confidence * 0.9; // Default implication confidence factor

          for (let i = 1; i < parts.length; i++) {
            if (parts[i].startsWith('confidence:')) {
              impliedConfidence = (parseInt(parts[i].substring('confidence:'.length), 10) / 100) * detectedTech.confidence;
              break;
            }
          }

          const impliedSig = signaturesDb.find(s => s.name === impliedName);
          if (impliedSig) {
            const existingImplied = finalDetectionMap.get(impliedName);
            if (!existingImplied || existingImplied.confidence < impliedConfidence) {
              finalDetectionMap.set(impliedName, {
                id: impliedSig.id, name: impliedSig.name,
                category: impliedSig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || impliedSig.category || 'Unknown',
                confidence: Math.min(1.0, impliedConfidence),
                detectionMethod: `Implied by: ${detectedTech.name}`,
                website: impliedSig.website, icon: impliedSig.icon, version: impliedSig.version,
                matchedValue: detectedTech.name
              });
              changedInPass = true;
            }
          }
        });
      }
    } // End of currentTechNames loop for implies

    // Re-iterate for requires/excludes after implications are settled in this pass
    const currentTechNamesForReqEx = Array.from(finalDetectionMap.keys());
    for (const techName of currentTechNamesForReqEx) {
        const sig = signaturesDb.find(s => s.name === techName);
        if (!sig) continue;

        // Requires
        if (sig.requires) {
            const requiredTechs = Array.isArray(sig.requires) ? sig.requires : [sig.requires];
            const allRequiredFound = requiredTechs.every(reqName => finalDetectionMap.has(reqName.split('\\;')[0]));
            if (!allRequiredFound) {
                if (finalDetectionMap.delete(techName)) changedInPass = true;
                continue;
            }
        }
        // Requires Category
        if (sig.requiresCategory) {
            const requiredCategories = Array.isArray(sig.requiresCategory) ? sig.requiresCategory : [sig.requiresCategory];
            const foundReqCategory = Array.from(finalDetectionMap.values()).some(detected =>
                requiredCategories.some(reqCatId => {
                    const catName = CATEGORIES[reqCatId.toString()] || `CatID-${reqCatId}`;
                    return detected.category.split(', ').includes(catName);
                })
            );
            if (!foundReqCategory) {
                 if (finalDetectionMap.delete(techName)) changedInPass = true;
                 continue;
            }
        }
        // Excludes
        if (sig.excludes) {
            const excludedTechs = Array.isArray(sig.excludes) ? sig.excludes : [sig.excludes];
            const anExcludedFound = excludedTechs.some(exName => finalDetectionMap.has(exName.split('\\;')[0]));
            if (anExcludedFound) {
                if (finalDetectionMap.delete(techName)) changedInPass = true;
            }
        }
    }
  } while (changedInPass);

  return Array.from(finalDetectionMap.values()).sort((a,b) => b.confidence - a.confidence);
}


export function addSignature(signature: TechnologySignature): void {
  if (signaturesDb.find(s => s.id === signature.id)) {
    console.warn(`[Signatures] Signature with ID ${signature.id} already exists. Not adding.`);
    return;
  }
  signaturesDb.push(signature);
  console.log(`[Signatures] Added signature: ${signature.name} (ID: ${signature.id})`);
}

export function deleteSignatureByName(name: string): void {
  const initialLength = signaturesDb.length;
  const newDb = signaturesDb.filter(sig => sig.name !== name);
  if (newDb.length < initialLength) {
    signaturesDb.length = 0;
    signaturesDb.push(...newDb);
    console.log(`[Signatures] Deleted signatures with name: ${name}`);
  } else {
    console.log(`[Signatures] No signatures found with name: ${name}`);
  }
}


    
