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
  '11': 'JavaScript Libraries',
  '12': 'Photo Galleries',
  '13': 'Wikis',
  '14': 'Hosting Panels',
  '15': 'Analytics',
  '18': 'Operating Systems',
  '19': 'Search Engines',
  '22': 'Web Servers',
  '25': 'Cache Tools',
  '26': 'Rich Text Editors',
  '27': 'JavaScript Frameworks', // Differentiated from Libraries
  '28': 'Maps',
  '29': 'Advertising Networks',
  '30': 'Network Devices',
  '31': 'Media Servers',
  '32': 'Webmail',
  '34': 'Payment Processors',
  '36': 'CDN',
  '47': 'UI Frameworks',
  '57': 'Programming Languages',
  '59': 'Database',
  '62': 'Security',
  '65': 'Font Scripts',
};


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
  dom?: string | string[] | Record<string, { // CSS selectors
    exists?: string; // empty string means just check existence
    text?: string; // regex
    attributes?: Record<string, string>; // attrName: regex value pattern
    properties?: Record<string, string>; // propName: regex value pattern
  }>;
  dns?: Record<string, string[]>; // e.g., { "MX": ["example\\.com"] }
  headers?: Record<string, string>; // headerName: regex value pattern
  html?: string | string[]; // regex patterns for raw HTML
  text?: string | string[]; // regex patterns for text content (HTML stripped)
  js?: Record<string, string>; // JS variable/property paths: regex value pattern
  meta?: Record<string, string>; // metaTagName: regex content pattern
  scriptSrc?: string | string[]; // regex for <script src="..."> URLs
  scripts?: string | string[]; // regex for inline <script> content or external script content
  url?: string | string[]; // regex for the page URL
  robots?: string | string[]; // regex for robots.txt content
  probe?: Record<string, string>; // path: regex for content at path
  xhr?: string | string[]; // regex for XHR/fetch request URLs

  // Relationships
  implies?: string | string[]; // Tech names or "TechName\\;confidence:XX"
  requires?: string | string[];
  requiresCategory?: number[];
  excludes?: string | string[];

  // Fields used by our system, can be derived or explicit
  id: string; // Unique ID for the signature (can be same as name or more specific)
  confidence?: number; // Base confidence for this specific signature rule if not in pattern (0.0-1.0)
  version?: string; // Static version if pattern doesn't extract it
  // versionCaptureGroup is superseded by ;version: tag in pattern
  detectionMethod?: string; // Auto-generated based on type
  category?: string; // Human-readable category from CATEGORIES
  // type is implicit from which field is used (e.g. if 'cookies' is present, it's a cookie type rule)
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
  // template is like \1, \2, or \1?trueVal:falseVal, or value\1
  // This is a simplified version
  return template.replace(/\\(\d)/g, (m, groupIndexStr) => {
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

function extractLinkHrefs(html: string): string[] {
  const linkRegex = /<link[^>]+href=["']([^"']+)["']/gi;
  const hrefs: string[] = [];
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    hrefs.push(match[1]);
  }
  return hrefs;
}

function extractMetaTags(html: string): Record<string, string[]> {
  const metaStore: Record<string, string[]> = {};
  const metaRegex = /<meta[^>]+(?:name|property)=["']([^"']+)["'][^>]+content=["']([^"']*)["']/gi;
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

function extractHtmlComments(html: string): string[] {
  const commentRegex = /<!--([\s\S]*?)-->/gi;
  const comments: string[] = [];
  let match;
  while ((match = commentRegex.exec(html)) !== null) {
    comments.push(match[1].trim());
  }
  return comments;
}

function extractCssClasses(html: string): string[] {
    const classRegex = /\sclass=["']([^"']+)["']/gi; // Ensure leading space or start of tag
    const classes = new Set<string>();
    let match;
    while((match = classRegex.exec(html)) !== null) {
        match[1].split(/\s+/).forEach(cls => cls && classes.add(cls));
    }
    return Array.from(classes);
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
  // Basic stripping of tags, script, style. For more accuracy, a proper parser would be needed.
  let text = html.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');
  text = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
  text = text.replace(/<!--[\s\S]*?-->/gi, '');
  text = text.replace(/<[^>]+>/g, ' ');
  return text.replace(/\s+/g, ' ').trim();
}

// Placeholder for cookie extraction logic (cookies are usually not in HTML, but from headers or document.cookie)
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


// --- Signatures Database (Examples) ---
// This needs to be significantly expanded.
export const signaturesDb: TechnologySignature[] = [
  // Example: React (from Wappalyzer's style)
  {
    id: 'React', name: 'React', cats: [27], website: 'https://reactjs.org/', icon: 'React.svg',
    js: { '__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size': '.+' }, // Check if the hook has renderers
    html: [
        "<[^>]+data-reactroot",
        "<[^>]+data-reactid"
    ],
    implies: "ReactDOM",
    description: "React is a JavaScript library for building user interfaces."
  },
  {
    id: 'ReactDOM', name: 'ReactDOM', cats: [27], website: 'https://reactjs.org/', icon: 'React.svg',
    scriptSrc: "react-dom(?:[-.]([\\d.]+))?(?:\\.min)?\\.js\\;version:\\1", // Example: react-dom.18.2.0.min.js
    description: "ReactDOM is the entry point of the DOM-related rendering paths for React."
  },
  {
    id: 'Next.js', name: 'Next.js', cats: [6, 27], website: 'https://nextjs.org/', icon: 'Next.js.svg',
    headers: { 'X-Powered-By': '^Next\\.js(?: ([\\d.]+))?\\;version:\\1' },
    html: '<script[^>]+id="__NEXT_DATA__"',
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
    js: { 'jQuery.fn.jquery': '([\\d.]+)\\;version:\\1' },
    description: "jQuery is a fast, small, and feature-rich JavaScript library."
  },
  {
    id: 'Google Analytics', name: 'Google Analytics', cats: [15], website: 'https://analytics.google.com/', icon: 'Google Analytics.svg',
    scriptSrc: [
      "googletagmanager\\.com/gtag/js\\?id=(UA-[\\d-]+-[\\d]+)", // GA Universal via GTM
      "google-analytics\\.com/analytics\\.js", // Classic GA
      "googletagmanager\\.com/gtag/js\\?id=(G-[A-Z0-9]+)" // GA4
    ],
    js: {
      'ga': '', // Check for global 'ga' object
      'gaplugins': '',
      '_gaq': '',
      'GoogleAnalyticsObject': '',
      'dataLayer.push': '\\arguments.+config.+(UA-|G-)' // Check for dataLayer push with GA ID
    },
    cookies: {
        '_ga': '',
        '_gid': ''
    },
    description: "Google Analytics is a web analytics service that tracks and reports website traffic."
  },
  {
    id: 'WordPress', name: 'WordPress', cats: [1], website: 'https://wordpress.org/', icon: 'WordPress.svg',
    meta: { 'generator': 'WordPress ([\\d.]+)\\;version:\\1' },
    html: '<link rel=[\'"]stylesheet[\'"] [^>]+wp-content',
    scriptSrc: '/wp-includes/',
    implies: 'PHP',
    description: "WordPress is a free and open-source content management system."
  },
  {
    id: 'PHP', name: 'PHP', cats: [57], website: 'https://php.net', icon: 'PHP.svg',
    headers: { 'X-Powered-By': 'PHP(?:/([\\d.]+))?\\;version:\\1' },
    url: '\\.php(?:$|\\?)',
    description: "PHP is a popular general-purpose scripting language that is especially suited to web development."
  },
  {
    id: 'Cloudflare', name: 'Cloudflare', cats: [36, 62], website: 'https://www.cloudflare.com/', icon: 'Cloudflare.svg',
    headers: {
        'Server': 'cloudflare',
        'cf-ray': '.+',
        '__cfduid': '.+' // Old cookie, less common now
    },
    cookies: { '__cf_bm': '.+'},
    description: "Cloudflare is a CDN, DNS, DDoS protection, and security service."
  },
  {
    id: 'Netflix', name: 'Netflix', cats: [], website: 'https://www.netflix.com', icon: 'Netflix.svg',
    url: 'netflix\\.com',
    js: {'netflix.reactContext':''}, // Example hypothetical JS object
    dom: {'[data-uia="player"]': {exists: ""}}, // Example hypothetical DOM element
    description: "Netflix is a streaming service."
  }
  // ... Many more signatures would be needed here
];

// --- Main Detection Function ---
export interface DetectionInput {
  url: string;
  htmlContent: string;
  headers?: Record<string, string | string[]>; // From server response
  cookies?: string; // From document.cookie or Set-Cookie headers
  robotsTxtContent?: string; // Content of /robots.txt
  // Future: Full script contents for 'scripts' type, DNS records, probe results
}

export function detectWithSignatures(input: DetectionInput): DetectedTechnologyInfo[] {
  const detectedStore = new Map<string, DetectedTechnologyInfo>();

  const { url, htmlContent, headers = {}, cookies: cookieString, robotsTxtContent } = input;

  const scriptSrcs = extractScriptSrcs(htmlContent);
  const linkHrefs = extractLinkHrefs(htmlContent);
  const metaTags = extractMetaTags(htmlContent); // { metaName: [content1, content2], ... }
  // const htmlComments = extractHtmlComments(htmlContent); // Currently unused, but available
  // const cssClasses = extractCssClasses(htmlContent); // Currently unused
  const inlineScriptContents = extractInlineScriptContents(htmlContent);
  const plainTextContent = extractTextContent(htmlContent);
  const documentCookies = extractDocumentCookies(cookieString); // { cookieName: value, ... }

  const processPattern = (
    valueToTest: string,
    patternStr: string,
    baseConfidence: number,
    sig: TechnologySignature,
    detectionMethodType: string,
    matchedDataSource: string
  ): DetectedTechnologyInfo | null => {
    const parsed = parseTaggedPattern(patternStr);
    const match = parsed.regex.exec(valueToTest);
    if (match) {
      const version = applyVersionTemplate(match, parsed.version);
      const confidence = (parsed.confidence ?? baseConfidence * 100) / 100; // Ensure 0-1 scale

      return {
        id: sig.id,
        name: sig.name,
        version: version || sig.version,
        confidence: Math.min(1.0, confidence),
        category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
        detectionMethod: `${detectionMethodType}: ${sig.name} (matched on ${matchedDataSource})`,
        matchedValue: match[0].length > 200 ? match[0].substring(0, 197) + '...' : match[0],
        website: sig.website,
        icon: sig.icon,
      };
    }
    return null;
  };

  signaturesDb.forEach(sig => {
    const baseConf = sig.confidence ?? 0.9; // Default base confidence if not in signature top-level

    // Helper to add/update detection
    const addOrUpdateDetection = (techInfo: DetectedTechnologyInfo | null) => {
      if (!techInfo) return;
      const existing = detectedStore.get(techInfo.name);
      if (!existing || techInfo.confidence > existing.confidence || (techInfo.confidence === existing.confidence && techInfo.version && !existing.version)) {
        detectedStore.set(techInfo.name, techInfo);
      }
    };

    // URL
    if (sig.url) {
      (Array.isArray(sig.url) ? sig.url : [sig.url]).forEach(p => {
        addOrUpdateDetection(processPattern(url, p, baseConf * 100, sig, 'URL', 'page URL'));
      });
    }

    // Headers
    if (sig.headers) {
      for (const headerName in sig.headers) {
        const headerPattern = sig.headers[headerName];
        const headerValue = headers[headerName.toLowerCase()] || headers[headerName];
        if (headerValue) {
          (Array.isArray(headerValue) ? headerValue : [headerValue]).forEach(val => {
            addOrUpdateDetection(processPattern(val, headerPattern, baseConf * 100, sig, 'Header', headerName));
          });
        }
      }
    }
    
    // Cookies
    if (sig.cookies) {
        for (const cookieName in sig.cookies) {
            const cookiePattern = sig.cookies[cookieName];
            if (documentCookies[cookieName]) {
                 addOrUpdateDetection(processPattern(documentCookies[cookieName], cookiePattern, baseConf * 100, sig, 'Cookie', cookieName));
            }
        }
    }

    // Meta tags
    if (sig.meta) {
      for (const metaName in sig.meta) {
        const metaPattern = sig.meta[metaName];
        if (metaTags[metaName.toLowerCase()]) {
          metaTags[metaName.toLowerCase()].forEach(content => {
            addOrUpdateDetection(processPattern(content, metaPattern, baseConf * 100, sig, 'Meta Tag', metaName));
          });
        }
      }
    }

    // scriptSrc
    if (sig.scriptSrc) {
      const sources = [...scriptSrcs, ...linkHrefs]; // Also check linkHrefs for scripts loaded via <link rel="preload" as="script"> etc.
      (Array.isArray(sig.scriptSrc) ? sig.scriptSrc : [sig.scriptSrc]).forEach(p => {
        sources.forEach(src => {
          addOrUpdateDetection(processPattern(src, p, baseConf * 100, sig, 'Script/Link Src', 'script/link tag'));
        });
      });
    }
    
    // scripts (inline script content)
    if (sig.scripts) {
        (Array.isArray(sig.scripts) ? sig.scripts : [sig.scripts]).forEach(p => {
            inlineScriptContents.forEach(scriptContent => {
                 addOrUpdateDetection(processPattern(scriptContent, p, baseConf * 100, sig, 'Inline Script', 'script content'));
            });
            // TODO: Optionally fetch and check external scripts if full JS execution environment is not available
        });
    }

    // html
    if (sig.html) {
        (Array.isArray(sig.html) ? sig.html : [sig.html]).forEach(p => {
            addOrUpdateDetection(processPattern(htmlContent, p, baseConf * 100, sig, 'HTML Content', 'raw HTML'));
        });
    }
    
    // text (plain text content)
    if (sig.text) {
        (Array.isArray(sig.text) ? sig.text : [sig.text]).forEach(p => {
            addOrUpdateDetection(processPattern(plainTextContent, p, baseConf * 100, sig, 'Text Content', 'page text'));
        });
    }

    // js (global variables/properties) - very simplified regex matching on inline scripts for now
    if (sig.js) {
        for (const jsPath in sig.js) {
            const jsPattern = sig.js[jsPath];
            // This is a huge simplification. Real 'js' detection needs JS execution.
            // We're just checking if the path fragments appear in inline scripts.
            // Example: jsPath = "jQuery.fn.jquery" -> check for "jQuery" and "fn" and "jquery"
            const pathParts = jsPath.split('.');
            let simplifiedJsSearchPattern = "";
            try {
                simplifiedJsSearchPattern = pathParts.map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[\\s\\S]*?'); // crude
            } catch (e) {
                console.warn(`[Signatures] Could not form JS search pattern for ${jsPath}`);
                continue;
            }

            if (simplifiedJsSearchPattern) {
                inlineScriptContents.forEach(scriptContent => {
                    addOrUpdateDetection(processPattern(scriptContent, `${simplifiedJsSearchPattern}(?:\\s*[:=]\\s*['"]?(${jsPattern})['"]?)?`, baseConf * 100, sig, 'JavaScript Var/Prop (Simplified)', jsPath));
                });
            }
        }
    }

    // TODO: Implement full support for these types, potentially involving tools in the AI flow
    // - dom: Requires a DOM parser (e.g., JSDOM) or browser context.
    // - dns: Requires DNS lookup capabilities.
    // - robots: Requires fetching /robots.txt (use robotsTxtContent if provided).
    // - probe: Requires making additional HTTP requests.
    // - xhr: Requires observing network requests (difficult without browser context).
    if (sig.robots && robotsTxtContent) {
        (Array.isArray(sig.robots) ? sig.robots : [sig.robots]).forEach(p => {
            addOrUpdateDetection(processPattern(robotsTxtContent, p, baseConf * 100, sig, 'robots.txt', 'robots.txt content'));
        });
    }

  });


  // --- Handle implies, requires, excludes (Simplified) ---
  const finalDetections = Array.from(detectedStore.values());
  const finalDetectionMap = new Map<string, DetectedTechnologyInfo>(finalDetections.map(d => [d.name, d]));

  // Requires (if a required tech is missing, remove the dependent tech)
  // This loop might need multiple passes if requires have chains
  let changedInRequiresPass = true;
  while(changedInRequiresPass) {
      changedInRequiresPass = false;
      signaturesDb.forEach(sig => {
          if (sig.requires && finalDetectionMap.has(sig.name)) {
              const requiredTechs = Array.isArray(sig.requires) ? sig.requires : [sig.requires];
              const allRequiredFound = requiredTechs.every(reqName => finalDetectionMap.has(reqName.split('\\;')[0])); // Simple check, ignore confidence/version from require string for now
              if (!allRequiredFound) {
                  finalDetectionMap.delete(sig.name);
                  changedInRequiresPass = true;
              }
          }
          // TODO: Add requiresCategory logic
      });
  }


  // Implies (if A implies B, and A is found, add B or boost B's confidence)
  finalDetectionMap.forEach(detectedTech => {
      const sig = signaturesDb.find(s => s.name === detectedTech.name);
      if (sig && sig.implies) {
          const impliedTechs = Array.isArray(sig.implies) ? sig.implies : [sig.implies];
          impliedTechs.forEach(impliedStr => {
              const parts = impliedStr.split('\\;');
              const impliedName = parts[0];
              let impliedConfidenceBoost = 0.1; // Default boost
              // TODO: Parse confidence from impliedStr if present e.g. "PHP\\;confidence:50"

              const impliedSig = signaturesDb.find(s => s.name === impliedName);
              if (impliedSig) {
                  let existingImplied = finalDetectionMap.get(impliedName);
                  if (!existingImplied) {
                      // Add implied tech with a base confidence (e.g. original tech's confidence * a factor)
                      finalDetectionMap.set(impliedName, {
                          id: impliedSig.id,
                          name: impliedSig.name,
                          category: impliedSig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || impliedSig.category || 'Unknown',
                          confidence: Math.min(1.0, (detectedTech.confidence * 0.8) + impliedConfidenceBoost), // Heuristic
                          detectionMethod: `Implied by: ${detectedTech.name}`,
                          website: impliedSig.website,
                          icon: impliedSig.icon,
                          version: impliedSig.version, // Cannot usually get version from implication
                      });
                  } else {
                      // Optionally boost confidence if already detected
                      existingImplied.confidence = Math.min(1.0, existingImplied.confidence + impliedConfidenceBoost);
                      if (!existingImplied.detectionMethod.includes('Implied by')) {
                        existingImplied.detectionMethod += ` (also implied by ${detectedTech.name})`;
                      }
                  }
              }
          });
      }
  });
  
  // TODO: Handle 'excludes' logic (if A excludes B, and both detected, decide what to do e.g. lower confidence, remove one)

  return Array.from(finalDetectionMap.values());
}


// --- Dynamic Signature Management (Examples - not typically used at runtime in this flow, but demonstrates extensibility) ---

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
  // Remove all signatures with this name
  const newDb = signaturesDb.filter(sig => sig.name !== name);
  if (newDb.length < initialLength) {
    signaturesDb.length = 0; // Clear original array
    signaturesDb.push(...newDb); // Push filtered items
    console.log(`[Signatures] Deleted signatures with name: ${name}`);
  } else {
    console.log(`[Signatures] No signatures found with name: ${name}`);
  }
}