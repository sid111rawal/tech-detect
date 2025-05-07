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
  css?: string | string[]; // regex for CSS rules

  // Relationships
  implies?: string | string[]; // Tech names or "TechName\\;confidence:XX"
  requires?: string | string[];
  requiresCategory?: number[];
  excludes?: string | string[];

  // Fields used by our system, can be derived or explicit
  id: string; // Unique ID for the signature (can be same as name or more specific)
  confidence?: number; // Base confidence for this specific signature rule if not in pattern (0.0-1.0)
  version?: string; // Static version if pattern doesn't extract it
  detectionMethod?: string; // Auto-generated based on type
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

    // Handle ternary conditional: \1?trueVal:falseVal or \1?trueVal
    const ternaryMatch = template.match(/^\\(\d)\?(.*?)(?::(.*?))?$/);
    if (ternaryMatch) {
        const groupIndex = parseInt(ternaryMatch[1], 10);
        const trueVal = ternaryMatch[2];
        const falseVal = ternaryMatch[3]; // Might be undefined
        if (match[groupIndex]) {
            return trueVal;
        } else if (falseVal !== undefined) {
            return falseVal;
        }
        return undefined; // Condition true, no trueVal, or condition false, no falseVal
    }

    // Handle simple replacement: value\1 or just \1
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
  // Regex to capture name or property attribute for meta tags
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
    const classRegex = /\sclass=["']([^"']+)["']/gi; 
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


// --- Signatures Database (Examples) ---
export const signaturesDb: TechnologySignature[] = [
  {
    id: 'React', name: 'React', cats: [27], website: 'https://reactjs.org/', icon: 'React.svg',
    js: { '__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size': '.+' },
    html: [
        "<[^>]+data-reactroot",
        "<[^>]+data-reactid"
    ],
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
    id: 'Google Analytics', name: 'Google Analytics', cats: [10], website: 'https://analytics.google.com/', icon: 'Google Analytics.svg',
    scriptSrc: [
      "googletagmanager\\.com/gtag/js\\?id=(UA-[\\d-]+-[\\d]+)", 
      "google-analytics\\.com/analytics\\.js", 
      "googletagmanager\\.com/gtag/js\\?id=(G-[A-Z0-9]+)" 
    ],
    js: {
      'ga': '', 'gaplugins': '', '_gaq': '', 'GoogleAnalyticsObject': '',
      'dataLayer.push': '\\arguments.+config.+(UA-|G-)'
    },
    cookies: { '_ga': '', '_gid': '' },
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
    headers: { 'Server': 'cloudflare', 'cf-ray': '.+' },
    cookies: { '__cf_bm': '.+', '__cfduid': '.+' }, // __cfduid is older but might still appear
    js: { 'Cloudflare': '' }, // Check for Cloudflare specific JS objects if any are exposed
    description: "Cloudflare is a CDN, DNS, DDoS protection, and security service."
  },
  { // From screenshot
    id: 'Zipkin', name: 'Zipkin', cats: [70], website: 'https://zipkin.io/', icon: 'Zipkin.svg', // Assuming an icon name
    headers: {
      'X-B3-TraceId': '.+',
      'X-B3-SpanId': '.+'
    },
    description: "Zipkin is a distributed tracing system."
  },
  { // From screenshot
    id: 'Emotion', name: 'Emotion', cats: [47], website: 'https://emotion.sh/', icon: 'Emotion.png', // Often .png or .svg
    html: '<style[^>]+data-emotion(?:-css)?=', // Matches <style data-emotion="css"> or <style data-emotion-css="...">
    js: { 'caches.inserted': '' }, // Emotion's cache object often has 'inserted'
    // dom: { '[class*="css-"]': {exists: ""} } // CSS class pattern, needs robust DOM parsing
    description: "Emotion is a library designed for writing CSS styles with JavaScript."
  },
  { // From screenshot
    id: 'HSTS', name: 'HSTS', cats: [62], website: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security', icon: 'HSTS.svg', // Generic security icon
    headers: { 'Strict-Transport-Security': '.+' },
    description: "HTTP Strict Transport Security (HSTS) is a web security policy mechanism."
  },
  { // From screenshot
    id: 'Open Graph', name: 'Open Graph', cats: [40, 69], website: 'https://ogp.me/', icon: 'OpenGraph.svg',
    meta: {
      'og:title': '.+',
      'og:type': '.+',
      // Add more common OG tags if needed
    },
    html: '<html[^>]+prefix="og:', // Check for prefix in html tag
    description: "The Open Graph protocol enables any web page to become a rich object in a social graph."
  },
  { // From screenshot
    id: 'BitPay', name: 'BitPay', cats: [34], website: 'https://bitpay.com/', icon: 'BitPay.svg',
    scriptSrc: 'bitpay\\.com/bitpay\\.js',
    html: '<iframe[^>]+id="bitpay"',
    js: { 'bitpay': '' },
    description: "BitPay provides Bitcoin and crypto payment processing services."
  },
  { // From screenshot
    id: 'Lodash', name: 'Lodash', cats: [11], website: 'https://lodash.com/', icon: 'Lodash.svg',
    scriptSrc: 'lodash(?:\\.min)?\\.js.*(?:version=([\\d\\.]+))?\\;version:\\1', // Example if version in query
    js: { '_.VERSION': '([\\d\\.]+)\\;version:\\1' }, // Primary way to get version
    html: '<!-- Lodash ([\\d\\.]+) -->\\;version:\\1', // Less common
    description: "Lodash is a modern JavaScript utility library delivering modularity, performance, & extras."
  },
  { // From screenshot
    id: 'Envoy', name: 'Envoy', cats: [66, 22], website: 'https://www.envoyproxy.io/', icon: 'Envoy.svg',
    headers: {
      'server': '(?:envoy|Envoy)',
      'x-envoy-upstream-service-time': '.+'
    },
    description: "Envoy is an open source edge and service proxy, designed for cloud-native applications."
  },
  { // From screenshot
    id: 'OneTrust', name: 'OneTrust', cats: [68, 42], website: 'https://www.onetrust.com/', icon: 'OneTrust.svg',
    scriptSrc: '(?:cdn\\.cookielaw\\.org|optanon\\.blob\\.core\\.windows\\.net)',
    cookies: { 'OptanonConsent': '.+', 'OptanonAlertBoxClosed': '.+' },
    html: '<div[^>]+id="onetrust-banner-sdk"',
    js: { 'Optanon': '' , 'OneTrust': ''},
    description: "OneTrust is a privacy, security, and data governance software provider."
  },
  {
    id: 'Netflix', name: 'Netflix', cats: [31], website: 'https://www.netflix.com', icon: 'Netflix.svg',
    url: 'netflix\\.com',
    js: {'netflix.reactContext':''}, // Example hypothetical JS object
    // dom: {'[data-uia="player"]': {exists: ""}}, // Example hypothetical DOM element - needs DOM parsing
    html: '<body[^>]+class="netflix-sans"',
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
  robotsTxtContent?: string; // Content of /robots.txt
}

export function detectWithSignatures(input: DetectionInput): DetectedTechnologyInfo[] {
  const detectedStore = new Map<string, DetectedTechnologyInfo>();

  const { url, htmlContent, headers = {}, cookies: cookieString, robotsTxtContent } = input;

  const scriptSrcs = extractScriptSrcs(htmlContent);
  const linkHrefs = extractLinkHrefs(htmlContent);
  const metaTags = extractMetaTags(htmlContent); 
  const inlineScriptContents = extractInlineScriptContents(htmlContent);
  const plainTextContent = extractTextContent(htmlContent);
  const documentCookies = extractDocumentCookies(cookieString); 

  const processPattern = (
    valueToTest: string,
    patternStr: string,
    baseConfidence: number, // This is already 0-1 from sig.confidence
    sig: TechnologySignature,
    detectionMethodType: string,
    matchedDataSource: string
  ): DetectedTechnologyInfo | null => {
    const parsed = parseTaggedPattern(patternStr);
    const match = parsed.regex.exec(valueToTest);
    if (match) {
      const versionFromPattern = applyVersionTemplate(match, parsed.version);
      // Confidence from pattern is 0-100, convert to 0-1. If not present, use baseConfidence from signature.
      const confidenceFromTag = parsed.confidence !== undefined ? parsed.confidence / 100 : baseConfidence;
      
      // If signature has top-level confidence, it might be an override or default.
      // Wappalyzer's logic: pattern confidence overrides signature confidence.
      const finalConfidence = confidenceFromTag;

      return {
        id: sig.id,
        name: sig.name,
        version: versionFromPattern || sig.version, // Prefer version from pattern
        confidence: Math.min(1.0, Math.max(0, finalConfidence)), // Clamp between 0 and 1
        category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
        detectionMethod: `${detectionMethodType}: ${sig.name} (on ${matchedDataSource})`,
        matchedValue: match[0].length > 200 ? match[0].substring(0, 197) + '...' : match[0],
        website: sig.website,
        icon: sig.icon,
      };
    }
    return null;
  };

  signaturesDb.forEach(sig => {
    // Wappalyzer default confidence is 100 if not specified by pattern.
    // Here, sig.confidence is the base if pattern doesn't specify one.
    const basePatternConfidence = sig.confidence ?? 1.0; 

    const addOrUpdateDetection = (techInfo: DetectedTechnologyInfo | null) => {
      if (!techInfo) return;
      const existing = detectedStore.get(techInfo.name);
      if (!existing || techInfo.confidence > existing.confidence || (techInfo.confidence === existing.confidence && techInfo.version && !existing.version)) {
        detectedStore.set(techInfo.name, techInfo);
      }
    };

    if (sig.url) {
      (Array.isArray(sig.url) ? sig.url : [sig.url]).forEach(p => {
        addOrUpdateDetection(processPattern(url, p, basePatternConfidence, sig, 'URL', 'page URL'));
      });
    }

    if (sig.headers) {
      for (const headerName in sig.headers) {
        const headerPattern = sig.headers[headerName];
        const headerValueFromServer = headers[headerName.toLowerCase()] || headers[headerName];
        if (headerValueFromServer) {
          (Array.isArray(headerValueFromServer) ? headerValueFromServer : [headerValueFromServer]).forEach(val => {
            addOrUpdateDetection(processPattern(val, headerPattern, basePatternConfidence, sig, 'Header', headerName));
          });
        }
      }
    }
    
    if (sig.cookies) {
        for (const cookieName in sig.cookies) {
            const cookiePattern = sig.cookies[cookieName];
            if (documentCookies[cookieName]) {
                 addOrUpdateDetection(processPattern(documentCookies[cookieName], cookiePattern, basePatternConfidence, sig, 'Cookie', cookieName));
            }
             // Also check against the raw cookie string for patterns that might span multiple cookies or are malformed
            if (cookieString && cookiePattern.includes(cookieName)) { // Heuristic: if pattern mentions cookiename
                 addOrUpdateDetection(processPattern(cookieString, cookiePattern, basePatternConfidence * 0.8, sig, 'Cookie String', 'raw cookies')); // lower confidence
            }
        }
    }

    if (sig.meta) {
      for (const metaNameKey in sig.meta) { // metaNameKey is like "generator" or "og:title"
        const metaPattern = sig.meta[metaNameKey];
        if (metaTags[metaNameKey.toLowerCase()]) { // metaTags keys are already lowercased
          metaTags[metaNameKey.toLowerCase()].forEach(content => {
            addOrUpdateDetection(processPattern(content, metaPattern, basePatternConfidence, sig, 'Meta Tag', metaNameKey));
          });
        }
      }
    }

    if (sig.scriptSrc) {
      const sources = [...scriptSrcs, ...linkHrefs]; 
      (Array.isArray(sig.scriptSrc) ? sig.scriptSrc : [sig.scriptSrc]).forEach(p => {
        sources.forEach(src => {
          addOrUpdateDetection(processPattern(src, p, basePatternConfidence, sig, 'Script/Link Src', 'script/link tag'));
        });
      });
    }
    
    if (sig.scripts) {
        (Array.isArray(sig.scripts) ? sig.scripts : [sig.scripts]).forEach(p => {
            inlineScriptContents.forEach(scriptContent => {
                 addOrUpdateDetection(processPattern(scriptContent, p, basePatternConfidence, sig, 'Inline Script', 'script content'));
            });
        });
    }

    if (sig.html) {
        (Array.isArray(sig.html) ? sig.html : [sig.html]).forEach(p => {
            addOrUpdateDetection(processPattern(htmlContent, p, basePatternConfidence, sig, 'HTML Content', 'raw HTML'));
        });
    }
    
    if (sig.text) {
        (Array.isArray(sig.text) ? sig.text : [sig.text]).forEach(p => {
            addOrUpdateDetection(processPattern(plainTextContent, p, basePatternConfidence, sig, 'Text Content', 'page text'));
        });
    }

    if (sig.js) { // Simplified JS check
        for (const jsPath in sig.js) {
            const jsObjPattern = sig.js[jsPath]; // This is the regex for the *value* of the property or an empty string for existence
            const pathParts = jsPath.split('.');
            
            let existsPatternStr = pathParts.map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('(?:\\s*\\.\\s*|\\s*\\[\\s*[\'"]?');
            pathParts.forEach((_,i) => { if (i < pathParts.length -1) existsPatternStr += "[\'\" ]? \\s* \\]?)";});


            const valueRegex = jsObjPattern ? `(?:\\s*[:=]\\s*(?:['"]?(.*?)['"]?|({[^}]*})))` : '';
            const fullPatternForExistenceOrValue = `${existsPatternStr}${valueRegex}`;

            inlineScriptContents.forEach(scriptContent => {
                const parsedForScript = parseTaggedPattern(fullPatternForExistenceOrValue + (jsObjPattern ? `\\;version:\\1` : ''));
                const match = parsedForScript.regex.exec(scriptContent);

                if (match) {
                    const versionFromJs = applyVersionTemplate(match, parsedForScript.version);
                    const confidenceFromTag = parsedForScript.confidence !== undefined ? parsedForScript.confidence / 100 : basePatternConfidence;
                    
                    addOrUpdateDetection({
                        id: sig.id, name: sig.name,
                        version: versionFromJs || sig.version,
                        confidence: Math.min(1.0, confidenceFromTag),
                        category: sig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || sig.category || 'Unknown',
                        detectionMethod: `JavaScript Var/Prop: ${sig.name} (on ${jsPath})`,
                        matchedValue: match[0].length > 100 ? match[0].substring(0,97) + "..." : match[0],
                        website: sig.website, icon: sig.icon,
                    });
                }
            });
        }
    }
    if (sig.robots && robotsTxtContent) {
        (Array.isArray(sig.robots) ? sig.robots : [sig.robots]).forEach(p => {
            addOrUpdateDetection(processPattern(robotsTxtContent, p, basePatternConfidence, sig, 'robots.txt', 'robots.txt content'));
        });
    }
  });


  const finalDetectionsList = Array.from(detectedStore.values());
  const finalDetectionMap = new Map<string, DetectedTechnologyInfo>(finalDetectionsList.map(d => [d.name, d]));

  let impliesChanged = true;
  while(impliesChanged){
    impliesChanged = false;
    finalDetectionMap.forEach(detectedTech => {
        const sig = signaturesDb.find(s => s.name === detectedTech.name);
        if (sig && sig.implies) {
            const impliedTechs = Array.isArray(sig.implies) ? sig.implies : [sig.implies];
            impliedTechs.forEach(impliedStr => {
                const parts = impliedStr.split('\\;');
                const impliedName = parts[0];
                let impliedConfidence = detectedTech.confidence * 0.8; // Default implication confidence factor

                for (let i = 1; i < parts.length; i++) {
                    if (parts[i].startsWith('confidence:')) {
                        impliedConfidence = parseInt(parts[i].substring('confidence:'.length), 10) / 100;
                        break;
                    }
                }

                const impliedSig = signaturesDb.find(s => s.name === impliedName);
                if (impliedSig) {
                    const existingImplied = finalDetectionMap.get(impliedName);
                    if (!existingImplied) {
                        finalDetectionMap.set(impliedName, {
                            id: impliedSig.id, name: impliedSig.name,
                            category: impliedSig.cats?.map(c => CATEGORIES[c.toString()] || `CatID-${c}`).join(', ') || impliedSig.category || 'Unknown',
                            confidence: Math.min(1.0, impliedConfidence),
                            detectionMethod: `Implied by: ${detectedTech.name}`,
                            website: impliedSig.website, icon: impliedSig.icon, version: impliedSig.version,
                        });
                        impliesChanged = true;
                    } else if (existingImplied.confidence < impliedConfidence) {
                        existingImplied.confidence = Math.min(1.0, impliedConfidence);
                        if (!existingImplied.detectionMethod.includes(`Implied by: ${detectedTech.name}`)) {
                           existingImplied.detectionMethod += ` (also implied by ${detectedTech.name})`;
                        }
                        impliesChanged = true;
                    }
                }
            });
        }
    });
  }
  
  // Requires & Excludes (Simplified: just remove if condition not met / conflict exists)
  let requiresExcludesChanged = true;
  while(requiresExcludesChanged) {
    requiresExcludesChanged = false;
    const currentTechNames = Array.from(finalDetectionMap.keys());
    for (const techName of currentTechNames) {
        const sig = signaturesDb.find(s => s.name === techName);
        if (!sig) continue;

        if (sig.requires) {
            const requiredTechs = Array.isArray(sig.requires) ? sig.requires : [sig.requires];
            const allRequiredFound = requiredTechs.every(reqName => finalDetectionMap.has(reqName.split('\\;')[0]));
            if (!allRequiredFound) {
                if (finalDetectionMap.delete(techName)) requiresExcludesChanged = true;
                continue; 
            }
        }
        if (sig.requiresCategory) {
            const requiredCategories = Array.isArray(sig.requiresCategory) ? sig.requiresCategory : [sig.requiresCategory];
            const foundReqCategory = Array.from(finalDetectionMap.values()).some(detected => 
                requiredCategories.some(reqCatId => (detected.category.split(', ').includes(CATEGORIES[reqCatId.toString()]) || detected.category.includes(`CatID-${reqCatId}`)))
            );
            if (!foundReqCategory) {
                 if (finalDetectionMap.delete(techName)) requiresExcludesChanged = true;
                 continue;
            }
        }
        if (sig.excludes) {
            const excludedTechs = Array.isArray(sig.excludes) ? sig.excludes : [sig.excludes];
            const anExcludedFound = excludedTechs.some(exName => finalDetectionMap.has(exName.split('\\;')[0]));
            if (anExcludedFound) {
                if (finalDetectionMap.delete(techName)) requiresExcludesChanged = true;
            }
        }
    }
  }

  return Array.from(finalDetectionMap.values());
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
