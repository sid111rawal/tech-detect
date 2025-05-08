/**
 * TechDetective Pro - Technology Signatures
 *
 * This file contains the signature database for detecting web technologies.
 * Enhanced with patterns for obfuscated/minified code detection.
 */
import type { PageContentResult } from '@/services/page-retriever'; // Ensure this matches the updated interface
import { retrieveRobotsTxt } from '@/services/page-retriever';
import type { SslCertificateInfo } from '@/services/network-info';


// Define the structure for a single pattern within a signature
export interface Pattern {
  type: 'html' | 'script' | 'css' | 'header' | 'meta' | 'cookie' | 'jsGlobal' | 'networkRequest' | 'jsVersion' | 'htmlComment' | 'filePath' | 'robots' | 'error' | 'dom';
  pattern: RegExp | string | Record<string, any>; // RegExp for most, string for names, object for DOM
  value?: RegExp | string | Record<string, any>; // For header value, meta content, cookie value, DOM attribute/text value
  weight?: number;         // Confidence multiplier (0.0 to 1.0), defaults to 1
  versionProperty?: string; // For jsVersion type (e.g., "$.fn.jquery")
  versionCaptureGroup?: number; // For version extraction from pattern or value regex, 1-based
  implies?: string[]; // Technologies implied by this specific pattern match
  confidence?: string; // Wappalyzer-style confidence tag, e.g. ";confidence:50"
  version?: string; // Wappalyzer-style version tag, e.g. ";version:\\1"
}

// Define the structure for a version definition within a signature
export interface VersionDefinition {
  weight?: number;          // Base confidence for this version if its patterns match
  patterns: Pattern[];
  implies?: string[];
}

// Define the structure for a technology signature (Wappalyzer-inspired)
export interface SignatureDefinition {
  name: string; // Implicitly the key in the categories object
  description?: string;
  website?: string;
  icon?: string; // Filename of the icon
  cpe?: string; // Common Platform Enumeration
  saas?: boolean;
  oss?: boolean;
  pricing?: string[]; // e.g. ["low", "freemium", "recurring"]
  
  cats?: number[]; // Wappalyzer category IDs (for reference, not primary use here)
  
  // Detection patterns (can be string, array of strings, or object for complex types)
  cookies?: Record<string, string | RegExp> | string | string[];
  dom?: string | string[] | Record<string, {
      exists?: string;
      attributes?: Record<string, string | RegExp>;
      properties?: Record<string, string | RegExp>;
      text?: string | RegExp;
  }>;
  dns?: Record<string, (string | RegExp)[]>; // e.g. { "MX": ["example\\.com"] }
  js?: Record<string, string | RegExp> | string | string[]; // JS properties/globals
  headers?: Record<string, string | RegExp> | string | string[];
  html?: string | string[] | RegExp;
  text?: string | string[] | RegExp; // Plain text matching
  css?: string | string[] | RegExp; // CSS rules
  probe?: Record<string, string | RegExp>; // Path: content pattern
  robots?: string | string[] | RegExp;
  url?: string | string[] | RegExp;
  xhr?: string | string[] | RegExp; // Hostnames of XHR requests
  meta?: Record<string, string | RegExp> | string | string[];
  scriptSrc?: string | string[] | RegExp;
  scripts?: string | string[] | RegExp; // Inline/external script content

  implies?: string | string[]; // Techs implied by this one
  requires?: string | string[]; // Techs required for this one
  requiresCategory?: string | string[]; // Categories required
  excludes?: string | string[]; // Techs excluded by this one

  // Internal fields for easier processing by our engine
  _normalizedPatterns?: Pattern[]; // Store normalized patterns here after parsing Wappalyzer format
  _weight?: number; // Our internal overall confidence if not using Wappalyzer's per-pattern confidence much

  // Fallback for simpler structure if not using Wappalyzer's direct fields
  patterns?: Pattern[]; // Our original pattern array
  versions?: { // Our original versions object
    [versionName: string]: VersionDefinition | Pattern[]; 
    versionProperty?: string; 
    patterns?: Pattern[];
  };
  versionProperty?: string; 
}


// Combine all signatures into a single database object
// The category is now primarily determined by the file name / import source
export interface SignaturesDatabase {
  analytics: Record<string, SignatureDefinition>;
  utility_libraries: Record<string, SignatureDefinition>;
  payment_processors: Record<string, SignatureDefinition>;
  security: Record<string, SignatureDefinition>;
  miscellaneous: Record<string, SignatureDefinition>;
  cookie_compliance: Record<string, SignatureDefinition>;
  self_hosted_cms: Record<string, SignatureDefinition>;
  hosted_cms: Record<string, SignatureDefinition>;
  css_frameworks: Record<string, SignatureDefinition>;
  server_platforms: Record<string, SignatureDefinition>;
  hosting_providers: Record<string, SignatureDefinition>;
  reverse_proxies: Record<string, SignatureDefinition>;
  programming_languages: Record<string, SignatureDefinition>;
  databases: Record<string, SignatureDefinition>;
  marketing_automation: Record<string, SignatureDefinition>;
}

// Function to convert Wappalyzer-style definition fields to our Pattern array
function normalizeWappalyzerPatterns(sigDef: SignatureDefinition): Pattern[] {
    const patterns: Pattern[] = [];
    const wappalyzerPatternFields: Array<keyof SignatureDefinition> = [
        'cookies', 'dom', 'dns', 'js', 'headers', 'html', 'text', 'css', 'probe', 
        'robots', 'url', 'xhr', 'meta', 'scriptSrc', 'scripts'
    ];

    const parsePatternString = (patternStr: string): { mainPattern: string | RegExp, confidence?: number, version?: string } => {
        const parts = patternStr.split('\\;');
        let mainPattern: string | RegExp = parts[0];
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
        
        // Do not automatically convert to RegExp here. Precompile step will handle it.
        // The mainPattern should remain a string if it's a regex string, or a literal string.
        return { mainPattern, confidence, version };
    };


    wappalyzerPatternFields.forEach(field => {
        const fieldValue = sigDef[field as keyof SignatureDefinition] as any;
        if (!fieldValue) return;

        const wappalyzerTypeToOurType = (wappField: string): Pattern['type'] | null => {
            switch(wappField) {
                case 'cookies': return 'cookie';
                case 'dom': return 'dom'; 
                case 'js': return 'jsGlobal'; 
                case 'headers': return 'header';
                case 'html': return 'html';
                case 'text': return 'html'; 
                case 'css': return 'css'; 
                case 'robots': return 'robots';
                case 'url': return 'filePath'; 
                case 'xhr': return 'networkRequest'; 
                case 'meta': return 'meta';
                case 'scriptSrc': return 'script'; 
                case 'scripts': return 'script'; 
                default: return null;
            }
        };
        
        const ourType = wappalyzerTypeToOurType(field);
        if (!ourType) return;

        if (typeof fieldValue === 'string') {
            const { mainPattern, confidence, version } = parsePatternString(fieldValue);
            patterns.push({ type: ourType, pattern: mainPattern, weight: confidence ? confidence / 100 : undefined, version });
        } else if (Array.isArray(fieldValue)) {
            fieldValue.forEach(item => {
                if (typeof item === 'string') {
                    const { mainPattern, confidence, version } = parsePatternString(item);
                    patterns.push({ type: ourType, pattern: mainPattern, weight: confidence ? confidence / 100 : undefined, version });
                } else if (item instanceof RegExp) { // Allow RegExp directly in arrays for Wappalyzer fields
                    patterns.push({ type: ourType, pattern: item });
                }
            });
        } else if (typeof fieldValue === 'object' && !(fieldValue instanceof RegExp)) {
            Object.entries(fieldValue).forEach(([key, value]) => { // value can be string | RegExp
                let valueMainPattern: string | RegExp;
                let valueConfidence: number | undefined;
                let valueVersion: string | undefined;

                if (typeof value === 'string') {
                    const parsedValue = parsePatternString(value);
                    valueMainPattern = parsedValue.mainPattern;
                    valueConfidence = parsedValue.confidence;
                    valueVersion = parsedValue.version;
                } else { // value is RegExp
                    valueMainPattern = value;
                }
                
                patterns.push({ 
                    type: ourType, 
                    pattern: key, 
                    value: valueMainPattern, 
                    weight: valueConfidence ? valueConfidence / 100 : undefined,
                    version: valueVersion 
                });
            });
        } else if (fieldValue instanceof RegExp) { // Top-level field is a RegExp
            patterns.push({ type: ourType, pattern: fieldValue });
        }
    });
    return patterns;
}


// Function to transform the imported Wappalyzer-like structure
function transformSignatures(
  categorySignaturesArray: SignatureDefinition[], 
  categoryName: string
): Record<string, SignatureDefinition> {
  const transformed: Record<string, SignatureDefinition> = {};
  categorySignaturesArray.forEach(originalSig => { 
    const techName = originalSig.name; 
    if (!techName) {
      console.warn(`[Signatures] Signature in category ${categoryName} is missing a name. Skipping.`);
      return;
    }
    transformed[techName] = {
      ...originalSig,
      name: techName, 
      _normalizedPatterns: normalizeWappalyzerPatterns(originalSig),
      _weight: originalSig._weight || 0.5 
    };
    if (originalSig.patterns) {
        transformed[techName]._normalizedPatterns = [
            ...(transformed[techName]._normalizedPatterns || []),
            ...originalSig.patterns!
        ];
    }
  });
  return transformed;
}

// Import signatures from modularized files
import { analyticsSignatures } from './signature-categories/analytics';
import { utilityLibrariesSignatures } from './signature-categories/utility_libraries';
import { paymentProcessorsSignatures } from './signature-categories/payment_processors';
import { securitySignatures } from './signature-categories/security';
import { miscellaneousSignatures } from './signature-categories/miscellaneous';
import { cookieComplianceSignatures } from './signature-categories/cookie_compliance';
import { selfHostedCmsSignatures } from './signature-categories/self_hosted_cms';
import { hostedCmsSignatures } from './signature-categories/hosted_cms';
import { cssFrameworksSignatures } from './signature-categories/css_frameworks';
import { serverPlatformsSignatures } from './signature-categories/server_platforms';
import { hostingProvidersSignatures } from './signature-categories/hosting_providers';
import { reverseProxiesSignatures } from './signature-categories/reverse_proxies';
import { programmingLanguagesSignatures } from './signature-categories/programming_languages';
import { databasesSignatures } from './signature-categories/databases';
import { marketingAutomationSignatures } from './signature-categories/marketing_automation';


const signaturesDb: SignaturesDatabase = {
  analytics: transformSignatures(analyticsSignatures, 'analytics'),
  utility_libraries: transformSignatures(utilityLibrariesSignatures, 'utility_libraries'),
  payment_processors: transformSignatures(paymentProcessorsSignatures, 'payment_processors'),
  security: transformSignatures(securitySignatures, 'security'),
  miscellaneous: transformSignatures(miscellaneousSignatures, 'miscellaneous'),
  cookie_compliance: transformSignatures(cookieComplianceSignatures, 'cookie_compliance'),
  self_hosted_cms: transformSignatures(selfHostedCmsSignatures, 'self_hosted_cms'),
  hosted_cms: transformSignatures(hostedCmsSignatures, 'hosted_cms'),
  css_frameworks: transformSignatures(cssFrameworksSignatures, 'css_frameworks'),
  server_platforms: transformSignatures(serverPlatformsSignatures, 'server_platforms'),
  hosting_providers: transformSignatures(hostingProvidersSignatures, 'hosting_providers'),
  reverse_proxies: transformSignatures(reverseProxiesSignatures, 'reverse_proxies'),
  programming_languages: transformSignatures(programmingLanguagesSignatures, 'programming_languages'),
  databases: transformSignatures(databasesSignatures, 'databases'),
  marketing_automation: transformSignatures(marketingAutomationSignatures, 'marketing_automation'),
};


// Precompile regex patterns for performance
function precompileSignatures(sigDb: SignaturesDatabase): SignaturesDatabase {
  for (const categoryKey in sigDb) {
    const category = sigDb[categoryKey as keyof SignaturesDatabase];
    for (const techName in category) {
      const sig = category[techName];
      const compileList = (patterns?: Pattern[]) => {
        patterns?.forEach(p => {
          // Compile p.pattern if it's a string meant to be a regex
          if (typeof p.pattern === 'string') {
            // For these types, p.pattern is a name/key, not usually a regex string unless explicitly formatted
            const isNonRegexPatternType = p.type === 'header' || p.type === 'meta' || p.type === 'jsGlobal' || p.type === 'dom' || p.type === 'cookie';
            if (!isNonRegexPatternType || (isNonRegexPatternType && p.pattern.startsWith('/') && p.pattern.endsWith('/'))) {
              try { 
                let patternString = p.pattern;
                if (isNonRegexPatternType && patternString.startsWith('/') && patternString.endsWith('/')) {
                    patternString = patternString.slice(1, -1); // Remove surrounding slashes for RegExp constructor
                }
                p.pattern = new RegExp(patternString.replace(/\\\\/g, '\\'), 'i'); 
              } 
              catch (e) { console.warn(`Invalid regex string for p.pattern '${p.pattern}' for ${sig.name}: ${p.type}`, e); }
            }
          }
          // Compile p.value if it's a string meant to be a regex
          if (p.value && typeof p.value === 'string') {
            try { p.value = new RegExp(p.value.replace(/\\\\/g, '\\'), 'i'); } 
            catch (e) { console.warn(`Invalid regex string for p.value '${p.value}' for ${sig.name}: ${p.type} - ${String(p.pattern)}`, e); }
          }
        });
      };
      compileList(sig._normalizedPatterns);
      compileList(sig.patterns); 
      if (sig.versions) {
        compileList(sig.versions.patterns);
        for (const versionName in sig.versions) {
          if (versionName === 'patterns' || versionName === 'versionProperty') continue;
          const versionDef = sig.versions[versionName];
          if (Array.isArray(versionDef)) {
            compileList(versionDef);
          } else if (typeof (versionDef as VersionDefinition).patterns === 'object') { 
             compileList((versionDef as VersionDefinition).patterns);
          }
        }
      }
    }
  }
  return sigDb;
}

const precompiledSignatures = precompileSignatures(JSON.parse(JSON.stringify(signaturesDb)));

export interface DetectedTechnologyInfo {
  id?: string;
  technology: string;
  version: string | null;
  confidence: number; // 0-100
  isHarmful?: boolean; // To be determined by separate logic if needed
  detectionMethod?: string;
  category: string; 
  categories?: string[]; 
  matchedValue?: string;
  website?: string;
  icon?: string;
  _meta?: {
    implies?: string | string[];
    requires?: string | string[];
    requiresCategory?: string | string[];
    excludes?: string | string[];
  };
}

export interface RedFlag {
  type: string; // e.g., "Missing Security Header", "Outdated Software", "SSL Issue"
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  recommendation?: string;
}


// --- Helper Extraction Functions ---
const extractJsVersions = (html: string, jsGlobals: string[]): Record<string, string | null> => {
  const versions: Record<string, string | null> = {};
  if (!html) return versions;

  const patterns: Record<string, RegExp> = {
    '$.fn.jquery': /\$\.fn\.jquery\s*=\s*['"]([^'"]+)['"]/i,
    'React.version': /React\.version\s*=\s*['"]([^'"]+)['"]/i,
    'Vue.version': /Vue\.version\s*=\s*['"]([^'"]+)['"]/i,
    'angular.version': /angular\.version\s*=\s*\{.*full:\s*['"]([^'"]+)['"]/i,
  };

  for (const prop in patterns) {
    const match = html.match(patterns[prop]);
    if (match && match[1]) {
      versions[prop] = match[1];
    }
  }
  // Ensure all version properties are initialized, even if not found
  for (const prop of ['$.fn.jquery', 'React.version', 'Vue.version', 'angular.version']) {
    if (!(prop in versions)) {
      versions[prop] = null;
    }
  }
  return versions;
};

const extractScripts = (html: string): { src: string[], content: string[] } => {
  const result: { src: string[], content: string[] } = { src: [], content: [] };
  if (!html) return result;
  const scriptSrcRegex = /<script[^>]*?src=["']([^"']+)["'][^>]*?>/gi;
  let match;
  while ((match = scriptSrcRegex.exec(html)) !== null) {
    result.src.push(match[1]);
  }
  const inlineScriptRegex = /<script(?![^>]*?type\s*=\s*(['"])(?:text\/template|application\/(?:ld\+)?json)\1)(?![^>]*?src)[^>]*?>([\s\S]*?)<\/script>/gi;
  while ((match = inlineScriptRegex.exec(html)) !== null) {
    if (match[2] && match[2].trim().length > 0) {
      result.content.push(match[2].trim());
    }
  }
  return result;
};

const extractCssLinks = (html: string): string[] => {
  const links: string[] = [];
  if (!html) return links;
  const cssRegex = /<link[^>]*?rel=["']stylesheet["'][^>]*?href=["']([^"']+)["'][^>]*?>/gi;
  let match;
  while ((match = cssRegex.exec(html)) !== null) {
    links.push(match[1]);
  }
  return links;
};

const extractMetaTags = (html: string): Record<string, string> => {
  const tags: Record<string, string> = {};
  if (!html) return tags;
  const metaRegex = /<meta[^>]*?(?:name|property)=["']([^"']+)["'][^>]*?content=["']([^"']*)["'][^>]*?>/gi;
  let match;
  while ((match = metaRegex.exec(html)) !== null) {
    tags[match[1].toLowerCase()] = match[2];
  }
  return tags;
};

const extractCookies = (setCookieStrings?: string[]): Array<{ name: string; value: string }> => {
  const cookiesArr: Array<{ name: string; value: string }> = [];
  if (setCookieStrings) {
    for (const cookieStr of setCookieStrings) {
      const firstPart = cookieStr.split(';')[0];
      const parts = firstPart.split('=');
      if (parts.length >= 1) {
        cookiesArr.push({ name: parts[0].trim(), value: parts.slice(1).join('=').trim() });
      }
    }
  }
  return cookiesArr;
};

const extractPotentialJsGlobals = (html: string): string[] => {
  const globals = new Set<string>();
  if (!html) return [];
  // Improved regex to catch more global definitions and common library references
  const globalPatterns = [
    /(?:var|let|const|window)\s*([a-zA-Z_$][\w$]*)\s*(?:=|\(|\[|\.)/g, // e.g. var foo = ...
    /(?:^|\W)([a-zA-Z_$][\w$]*)\s*=\s*(?:\{|function|\(|new\s)/g, // e.g. foo = function()...
    /\b([a-zA-Z_$][\w$]*)\s*(?:\.\s*[a-zA-Z_$][\w$]*)+\s*\(/g, // e.g. MyLib.someMethod(
    /\b(React|ReactDOM|Vue|jQuery|\$|_|angular|moment|gsap|THREE|Stripe|paypal|OneTrust|Optanon|dataLayer|gtag|ga|mixpanel|analytics|fbq|twq|Shopify|wp)\b/g
  ];
  
  for (const regex of globalPatterns) {
    let match;
    while ((match = regex.exec(html)) !== null) {
      globals.add(match[1] || match[0]); // match[0] for the last regex group
    }
  }
  return Array.from(globals);
};

const extractNetworkRequests = (html: string, scriptsSrc: string[], cssLinks: string[]): string[] => {
    const requests = new Set<string>();
    if (html) {
      // More comprehensive URL regex to capture various forms of URLs
      const urlRegex = /(['"`])((?:https?:)?\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*))\1/gi;
      let match;
      while ((match = urlRegex.exec(html)) !== null) {
          requests.add(match[2]);
      }
       // Look for fetch() or XMLHttpRequest patterns
      const fetchRegex = /fetch\s*\(\s*['"`]((?:https?:)?\/\/[^'"`\s]+)['"`]/gi;
      while ((match = fetchRegex.exec(html)) !== null) {
          requests.add(match[1]);
      }
      const xhrRegex = /xhr\.open\s*\([^,]+,\s*['"`]((?:https?:)?\/\/[^'"`\s]+)['"`]/gi;
       while ((match = xhrRegex.exec(html)) !== null) {
          requests.add(match[1]);
      }
    }
    scriptsSrc.forEach(s => requests.add(s));
    cssLinks.forEach(l => requests.add(l));
    return Array.from(requests);
};

const extractHtmlComments = (html: string): string[] => {
  const comments: string[] = [];
  if (!html) return comments;
  const commentRegex = /<!--([\s\S]*?)-->/gi;
  let match;
  while ((match = commentRegex.exec(html)) !== null) {
    comments.push(match[1].trim());
  }
  return comments;
};


// --- Core Detection Logic ---
function checkSinglePattern(
  patternDef: Pattern,
  htmlContent: string,
  extractedScripts: { src: string[], content: string[] },
  extractedCssLinks: string[],
  responseHeaders: Record<string, string | string[]>,
  extractedMetaTags: Record<string, string>,
  parsedCookies: Array<{ name: string; value: string }>,
  extractedJsGlobals: string[],
  extractedNetworkRequests: string[],
  extractedHtmlComments: string[],
  javaScriptVersions: Record<string, string | null>,
  currentUrl: string, 
  robotsContent: string | null, 
  errorPageContent: string | null
): { match: boolean; version?: string | null; matchedValue?: string; confidenceFactor: number } {

  let match = false;
  let version: string | null = null;
  let matchedString: string | undefined;
  let confidenceFactor = patternDef.weight !== undefined ? patternDef.weight : 1.0; 

  if (patternDef.confidence) { 
      const confValue = parseInt(patternDef.confidence.split(':')[1], 10);
      if (!isNaN(confValue)) confidenceFactor = confValue / 100;
  }

  const testRegex = (textToTest: string | undefined, regex: RegExp, versionTemplate?: string, versionGroup?: number) => {
    if (typeof textToTest !== 'string') return;
    const execResult = regex.exec(textToTest);
    if (execResult) {
      match = true;
      matchedString = execResult[0]; 
      if (versionTemplate) { 
          version = resolveVersionTemplate(versionTemplate, execResult);
      } else if (versionGroup && execResult[versionGroup]) {
        version = execResult[versionGroup];
      }
    }
  };
  
 const testString = (textToTest: string | undefined, str: string, isCaseSensitive: boolean = false) => {
    if (typeof textToTest === 'string' && typeof str === 'string') {
        if (isCaseSensitive ? textToTest.includes(str) : textToTest.toLowerCase().includes(str.toLowerCase())) {
            match = true;
            matchedString = str;
        }
    }
 };


  const resolveVersionTemplate = (template: string, execResult: RegExpExecArray): string | null => {
    return template.replace(/\\(\d+)/g, (m, groupIndexStr) => {
        const groupIndex = parseInt(groupIndexStr, 10);
        return execResult[groupIndex] || '';
    });
  };


  switch (patternDef.type) {
    case 'html':
      if (htmlContent && patternDef.pattern instanceof RegExp) testRegex(htmlContent, patternDef.pattern, patternDef.version, patternDef.versionCaptureGroup);
      else if (htmlContent && typeof patternDef.pattern === 'string') testString(htmlContent, patternDef.pattern);
      break;
    case 'script': 
      if (patternDef.pattern instanceof RegExp) {
        extractedScripts.src.forEach(s => testRegex(s, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup));
        if (!match) extractedScripts.content.forEach(s => testRegex(s, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup));
      } else if (typeof patternDef.pattern === 'string') {
        extractedScripts.src.forEach(s => testString(s, patternDef.pattern as string));
        if (!match) extractedScripts.content.forEach(s => testString(s, patternDef.pattern as string));
      }
      break;
    case 'css': 
      if (patternDef.pattern instanceof RegExp) extractedCssLinks.forEach(link => testRegex(link, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup));
      else if (typeof patternDef.pattern === 'string') extractedCssLinks.forEach(link => testString(link, patternDef.pattern as string));
      break;
    case 'header':
      if (typeof patternDef.pattern !== 'string') {
        break;
      }
      const headerKey = (patternDef.pattern as string).toLowerCase(); 
      const headerVal = responseHeaders[headerKey];
      if (headerVal) {
        const headerValStr = Array.isArray(headerVal) ? headerVal.join(', ') : headerVal;
        if (patternDef.value instanceof RegExp) {
          testRegex(headerValStr, patternDef.value, patternDef.version, patternDef.versionCaptureGroup);
        } else if (typeof patternDef.value === 'string') {
           testString(headerValStr, patternDef.value); // Header values can be case sensitive, use default case-insensitive for now
        } else { 
          match = true;
          matchedString = headerKey;
        }
      }
      break;
    case 'meta':
      if (typeof patternDef.pattern !== 'string' || (typeof patternDef.pattern === 'string' && !patternDef.pattern)) {
         break;
      }
      // Handle pattern being { name: 'meta-name', content: 'meta-content-pattern' } or just 'meta-name'
      const metaNameFromPattern = (typeof patternDef.pattern === 'object' && patternDef.pattern.name) ? patternDef.pattern.name : String(patternDef.pattern);
      const metaKey = metaNameFromPattern.toLowerCase();
      const metaContentPattern = (typeof patternDef.pattern === 'object' && patternDef.pattern.content) ? patternDef.pattern.content : patternDef.value;


      if (extractedMetaTags[metaKey]) { // Meta tag with this name exists
        if (metaContentPattern instanceof RegExp) {
            testRegex(extractedMetaTags[metaKey], metaContentPattern, patternDef.version, patternDef.versionCaptureGroup);
        } else if (typeof metaContentPattern === 'string') {
            testString(extractedMetaTags[metaKey], metaContentPattern);
        } else if (metaContentPattern === undefined || metaContentPattern === null || (typeof metaContentPattern === 'object' && Object.keys(metaContentPattern).length === 0 )) { 
            // No content pattern specified, or value for meta tag is not specified, just existence check
            match = true;
            matchedString = metaKey;
        }
      }
      break;
    case 'cookie':
        parsedCookies.forEach(cookie => {
            if (match) return; 
            let nameMatches = false;
            // Handle patternDef.pattern which could be a string (literal or regex string) or a RegExp object
            if (typeof patternDef.pattern === 'string') {
                if (patternDef.pattern.startsWith('/') && patternDef.pattern.endsWith('/')) { // It's a regex string like "/^_ga/i"
                    try {
                        const cookieNameRegex = new RegExp(patternDef.pattern.slice(1, -1), 'i');
                        if (cookieNameRegex.test(cookie.name)) nameMatches = true;
                    } catch (e) {
                        // console.warn(`[Signatures] Invalid regex string for cookie name pattern: ${patternDef.pattern}`, e);
                        if (cookie.name.toLowerCase() === patternDef.pattern.toLowerCase()) nameMatches = true; // Fallback to literal match
                    }
                } else { // It's a literal string
                    if (cookie.name.toLowerCase() === patternDef.pattern.toLowerCase()) nameMatches = true;
                }
            } else if (patternDef.pattern instanceof RegExp) { // It's already a RegExp object
                if (patternDef.pattern.test(cookie.name)) nameMatches = true;
            }


            if (nameMatches) {
                if (patternDef.value instanceof RegExp) { 
                    testRegex(cookie.value, patternDef.value, patternDef.version, patternDef.versionCaptureGroup);
                } else if (typeof patternDef.value === 'string') {
                   testString(cookie.value, patternDef.value);
                } else if (patternDef.value === undefined || patternDef.value === null) { 
                    match = true;
                    matchedString = cookie.name;
                }
            }
        });
        break;
    case 'jsGlobal': 
      const globalName = typeof patternDef.pattern === 'string' ? patternDef.pattern : String(patternDef.pattern); // Ensure it's a string
      if (extractedJsGlobals.some(g => g === globalName || (g && g.startsWith(globalName + ".")) ) ) { 
        match = true;
        matchedString = globalName;
        if (patternDef.value instanceof RegExp && javaScriptVersions[globalName]) { 
             testRegex(javaScriptVersions[globalName], patternDef.value, patternDef.version, patternDef.versionCaptureGroup);
        } else if (typeof patternDef.versionProperty === 'string' && javaScriptVersions[patternDef.versionProperty] !== null) {
            // This handles the case where patternDef.pattern is the global name like "jQuery"
            // and patternDef.versionProperty is "$.fn.jquery"
            // We need to extract version using the versionProperty
            version = javaScriptVersions[patternDef.versionProperty];
        }
      }
      break;
    case 'networkRequest': 
      if (patternDef.pattern instanceof RegExp) extractedNetworkRequests.forEach(req => testRegex(req, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup));
      else if (typeof patternDef.pattern === 'string') extractedNetworkRequests.forEach(req => testString(req, patternDef.pattern as string));
      break;
    case 'jsVersion': 
      if (patternDef.versionProperty && javaScriptVersions[patternDef.versionProperty] !== null) {
        const verStr = javaScriptVersions[patternDef.versionProperty];
        if (verStr && patternDef.pattern instanceof RegExp) {
          testRegex(verStr, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup || 1);
        } else if (verStr && typeof patternDef.pattern === 'string') { // If pattern is a string, direct match
            if (verStr === patternDef.pattern) {
                match = true;
                version = verStr;
                matchedString = `${patternDef.versionProperty}: ${verStr}`;
            }
        }
      }
      break;
    case 'htmlComment':
      if (patternDef.pattern instanceof RegExp) extractedHtmlComments.forEach(comment => testRegex(comment, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup));
      else if (typeof patternDef.pattern === 'string') extractedHtmlComments.forEach(comment => testString(comment, patternDef.pattern as string));
      break;
    case 'filePath': 
        if (patternDef.pattern instanceof RegExp) testRegex(currentUrl, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup);
        else if (typeof patternDef.pattern === 'string') testString(currentUrl, patternDef.pattern as string);
        break;
    case 'robots': 
        if (robotsContent && patternDef.pattern instanceof RegExp) testRegex(robotsContent, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup);
        else if (robotsContent && typeof patternDef.pattern === 'string') testString(robotsContent, patternDef.pattern as string);
        break;
    case 'error': 
        if (errorPageContent && patternDef.pattern instanceof RegExp) testRegex(errorPageContent, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup);
        else if (errorPageContent && typeof patternDef.pattern === 'string') testString(errorPageContent, patternDef.pattern as string);
        break;
    case 'dom':
        // Basic DOM check based on string inclusion, for more complex DOM checks, JSDOM or similar would be needed server-side
        // This current implementation of 'dom' type is limited for server-side string-based matching
        if (typeof patternDef.pattern === 'string' && htmlContent) { 
            const selector = patternDef.pattern; // e.g., "#example-id" or ".example-class" or "div[data-example]"
            // Simple check if selector-like string exists (highly approximate)
            const simplifiedSelector = selector.replace(/[#.]/g, '').replace(/\[.*?\]/g, ''); // Remove #, ., [attr=val] for basic check
            if (htmlContent.includes(simplifiedSelector)) { 
                if (typeof patternDef.value === 'object' && patternDef.value !== null) {
                    const domValue = patternDef.value as {exists?: string, attributes?: Record<string, string|RegExp>, text?: string|RegExp};
                    // For `exists` type DOM check, if simplifiedSelector is found, consider it a match
                    if (domValue.exists !== undefined) match = true; 
                    // Advanced attribute/text checks would require actual DOM parsing, not feasible with regex alone on raw HTML string
                } else {
                   match = true; // If no specific value checks, existence of simplified selector is enough for basic match
                }
                if (match) matchedString = patternDef.pattern;
            }
        }
        break;
    default:
      match = false;
  }
  return { match, version, matchedValue: matchedString, confidenceFactor };
}


export async function detectTechnologies(
  pageData: PageContentResult,
  finalUrl: string,
  sslInfo: SslCertificateInfo | null
): Promise<{ technologies: DetectedTechnologyInfo[], redFlags: RedFlag[] }> {
  let detectedTechMap: Map<string, DetectedTechnologyInfo> = new Map();
  const redFlags: RedFlag[] = [];

  const { html, headers = {}, setCookieStrings, status } = pageData;

  if (!html && Object.keys(headers).length === 0) {
    console.log("[Signatures] No HTML or headers to analyze.");
    return { technologies: [], redFlags: [] };
  }
  const htmlContent = html || "";

  const extractedScripts = extractScripts(htmlContent);
  const extractedCssLinks = extractCssLinks(htmlContent);
  const extractedMetaTags = extractMetaTags(htmlContent);
  const parsedCookies = extractCookies(setCookieStrings); 
  const extractedJsGlobals = extractPotentialJsGlobals(htmlContent);
  const extractedNetworkRequests = extractNetworkRequests(htmlContent, extractedScripts.src, extractedCssLinks);
  const extractedHtmlComments = extractHtmlComments(htmlContent);
  const javaScriptVersions = extractJsVersions(htmlContent, extractedJsGlobals);
  
  let robotsContent: string | null = null;
  const needsRobotsTxt = Object.values(precompiledSignatures).some(category => 
    Object.values(category).some(sig => 
        (sig._normalizedPatterns || []).some(p => p.type === 'robots') ||
        (sig.patterns || []).some(p => p.type === 'robots') ||
        (sig.versions && Object.values(sig.versions).some(vDefOrPatterns => {
            if(Array.isArray(vDefOrPatterns)) return vDefOrPatterns.some(p => p.type === 'robots');
            if (typeof vDefOrPatterns === 'object' && (vDefOrPatterns as VersionDefinition).patterns) {
                 return (vDefOrPatterns as VersionDefinition).patterns.some(p => p.type === 'robots');
            }
            return false;
        }))
    )
  );

  if (needsRobotsTxt) {
    try {
      robotsContent = await retrieveRobotsTxt(finalUrl);
    } catch (e) {
      console.warn(`[Signatures] Failed to fetch robots.txt for ${finalUrl}:`, e);
    }
  }
  
  const errorPageContent = (status && status >= 400) ? htmlContent : null;

  // --- Red Flag Generation ---
  // Missing HSTS
  if (!headers['strict-transport-security']) {
    redFlags.push({
      type: "Missing Security Header",
      message: "Strict-Transport-Security (HSTS) header is not set. This makes the site vulnerable to SSL stripping attacks.",
      severity: "medium",
      recommendation: "Implement HSTS header to enforce HTTPS."
    });
  }
  // Missing CSP
  if (!headers['content-security-policy'] && !extractedMetaTags['content-security-policy']) {
    redFlags.push({
      type: "Missing Security Header",
      message: "Content-Security-Policy (CSP) is not configured. This increases risk of XSS attacks.",
      severity: "medium",
      recommendation: "Implement CSP to control resources the browser is allowed to load."
    });
  }

  // SSL Certificate Issues
  if (sslInfo) {
    if (sslInfo.error) {
      redFlags.push({
        type: "SSL Issue",
        message: `SSL Certificate Error: ${sslInfo.error}`,
        severity: "high",
        recommendation: "Investigate and resolve the SSL certificate problem immediately."
      });
    } else if (sslInfo.validTo) {
      const expiryDate = new Date(sslInfo.validTo);
      const now = new Date();
      const daysUntilExpiry = (expiryDate.getTime() - now.getTime()) / (1000 * 3600 * 24);
      if (daysUntilExpiry < 0) {
        redFlags.push({
          type: "SSL Issue",
          message: `SSL Certificate has expired on ${sslInfo.validTo}.`,
          severity: "critical",
          recommendation: "Renew the SSL certificate immediately."
        });
      } else if (daysUntilExpiry < 30) {
        redFlags.push({
          type: "SSL Issue",
          message: `SSL Certificate is expiring soon (on ${sslInfo.validTo}, in ${Math.round(daysUntilExpiry)} days).`,
          severity: "medium",
          recommendation: "Renew the SSL certificate before it expires."
        });
      }
    }
  } else {
     redFlags.push({
        type: "SSL Issue",
        message: "Could not retrieve SSL certificate information. The site might not be using HTTPS or is not reachable on port 443.",
        severity: "medium",
        recommendation: "Ensure the website is accessible via HTTPS and has a valid SSL certificate."
      });
  }

  // Check for outdated jQuery as an example (could be expanded)
  const jQueryVersion = javaScriptVersions['$.fn.jquery'];
  if (jQueryVersion) {
    const majorVersion = parseInt(jQueryVersion.split('.')[0], 10);
    if (majorVersion < 3) {
      redFlags.push({
        type: "Outdated Software",
        message: `Using an outdated version of jQuery (${jQueryVersion}). This may have known security vulnerabilities.`,
        severity: "medium",
        recommendation: "Update jQuery to the latest stable version (3.x or higher)."
      });
    }
  }


  for (const categoryName in precompiledSignatures) {
    const categorySignatures = precompiledSignatures[categoryName as keyof SignaturesDatabase];
    for (const techName in categorySignatures) {
      const sigDef = categorySignatures[techName];
      let techOverallConfidence = 0;
      let techDetectedVersion: string | null = null;
      let techPrimaryMatchedValue: string | undefined;
      let techPrimaryDetectionMethod: string | undefined;
      let techMatchOccurred = false;
      let accumulatedImplications = new Set<string>();

      const baseSigConfidence = (sigDef._weight !== undefined ? sigDef._weight * 100 : 50);

      const processPatternsList = (patternsToProcess: Pattern[] | undefined, currentVersionNameForContext?: string) => {
        if (!patternsToProcess) return;

        for (const pDef of patternsToProcess) {
          const result = checkSinglePattern(
            pDef, htmlContent, extractedScripts, extractedCssLinks, headers,
            extractedMetaTags, parsedCookies, extractedJsGlobals, extractedNetworkRequests,
            extractedHtmlComments, javaScriptVersions, finalUrl, robotsContent, errorPageContent
          );

          if (result.match) {
            techMatchOccurred = true;
            let patternBaseWeight = baseSigConfidence / 100; 

            if (currentVersionNameForContext && sigDef.versions && sigDef.versions[currentVersionNameForContext]) {
                const versionInfo = sigDef.versions[currentVersionNameForContext];
                if (!Array.isArray(versionInfo) && (versionInfo as VersionDefinition).weight !== undefined) {
                    patternBaseWeight = (versionInfo as VersionDefinition).weight!;
                }
            }
            
            const currentPatternEffectiveConfidence = patternBaseWeight * result.confidenceFactor * 100;

            if (currentPatternEffectiveConfidence > techOverallConfidence) {
              techOverallConfidence = currentPatternEffectiveConfidence;
              techDetectedVersion = result.version || techDetectedVersion || (currentVersionNameForContext && currentVersionNameForContext !== 'patterns' && currentVersionNameForContext !== 'versionProperty' ? currentVersionNameForContext : null);
              techPrimaryMatchedValue = result.matchedValue;
              techPrimaryDetectionMethod = `Type: ${pDef.type}, Pattern: ${String(pDef.pattern).substring(0,50)}${pDef.value ? `, Value: ${String(pDef.value).substring(0,30)}` : ''}`;
            } else if (currentPatternEffectiveConfidence === techOverallConfidence && result.version && !techDetectedVersion) {
              techDetectedVersion = result.version;
              techPrimaryMatchedValue = result.matchedValue; 
              techPrimaryDetectionMethod = `Type: ${pDef.type}, Pattern: ${String(pDef.pattern).substring(0,50)}${pDef.value ? `, Value: ${String(pDef.value).substring(0,30)}` : ''}`;
            }
            
            // If pattern has a version string, use it directly (e.g. from Wappalyzer's "version:\\1")
            if (pDef.version && typeof pDef.version === 'string' && !techDetectedVersion) {
                techDetectedVersion = pDef.version; // This might need further processing if it contains backreferences
            }


            if (pDef.implies) pDef.implies.forEach(imp => accumulatedImplications.add(imp));
          }
        }
      };
      
      processPatternsList(sigDef._normalizedPatterns);

      if (sigDef.versions) {
        const globalVersionProp = sigDef.versions.versionProperty || sigDef.versionProperty;
        if (globalVersionProp && javaScriptVersions[globalVersionProp]) {
            const currentVersion = javaScriptVersions[globalVersionProp];
            let versionMatchedByName = false;
            for (const versionName in sigDef.versions) {
                 if (versionName === 'patterns' || versionName === 'versionProperty') continue;
                 if (currentVersion && versionName.includes(currentVersion.split('.')[0])) { 
                    const versionDetail = sigDef.versions[versionName];
                    if (Array.isArray(versionDetail)) {
                        processPatternsList(versionDetail, versionName);
                    } else if (typeof versionDetail === 'object' && (versionDetail as VersionDefinition).patterns){
                        processPatternsList((versionDetail as VersionDefinition).patterns, versionName);
                    }
                    if (techMatchOccurred) techDetectedVersion = techDetectedVersion || versionName; 
                    versionMatchedByName = true;
                    break;
                 }
            }
            if (techMatchOccurred && !techDetectedVersion && currentVersion) { 
                techDetectedVersion = currentVersion;
            }
        }
        for (const versionName in sigDef.versions) {
            if (versionName === 'patterns' || versionName === 'versionProperty') continue;
            const versionDetail = sigDef.versions[versionName];
            if (Array.isArray(versionDetail)) {
                processPatternsList(versionDetail, versionName);
            } else if (typeof versionDetail === 'object' && (versionDetail as VersionDefinition).patterns){
                processPatternsList((versionDetail as VersionDefinition).patterns, versionName);
            }
        }
        if (sigDef.versions.patterns) {
            processPatternsList(sigDef.versions.patterns);
        }
      }
      
      processPatternsList(sigDef.patterns);


      if (sigDef.implies) {
          (Array.isArray(sigDef.implies) ? sigDef.implies : [sigDef.implies]).forEach(imp => {
              const implyParts = imp.split('\\;');
              accumulatedImplications.add(implyParts[0]);
          });
      }


      if (techMatchOccurred && techOverallConfidence > 10) { 
        const finalConfidence = Math.min(100, Math.round(techOverallConfidence));
        const existing = detectedTechMap.get(sigDef.name);

        if (!existing || finalConfidence > existing.confidence || (finalConfidence === existing.confidence && techDetectedVersion && !existing.version)) {
          detectedTechMap.set(sigDef.name, {
            technology: sigDef.name,
            version: techDetectedVersion,
            confidence: finalConfidence,
            category: categoryName,
            categories: sigDef.cats?.map(String), 
            website: sigDef.website,
            icon: sigDef.icon,
            matchedValue: techPrimaryMatchedValue,
            detectionMethod: techPrimaryDetectionMethod,
            _meta: { 
                implies: Array.from(accumulatedImplications).concat(existing?._meta?.implies ? (Array.isArray(existing._meta.implies) ? existing._meta.implies : [existing._meta.implies]) : []),
                excludes: sigDef.excludes, 
                requires: sigDef.requires, 
                requiresCategory: sigDef.requiresCategory 
            }
          });
        } else if (existing && accumulatedImplications.size > 0) {
            const currentImplies = new Set(existing._meta?.implies ? (Array.isArray(existing._meta.implies) ? existing._meta.implies : [existing._meta.implies]) : []);
            accumulatedImplications.forEach(imp => currentImplies.add(imp));
            existing._meta!.implies = Array.from(currentImplies);
        }
      }
    }
  }

  let finalDetections = Array.from(detectedTechMap.values());
  let changedInPass = true;
  let maxPasses = 5; 
  let currentPass = 0;
  
  while(changedInPass && currentPass < maxPasses){
    changedInPass = false;
    currentPass++;
    const currentDetectionNames = new Set(finalDetections.map(t => t.technology));
    const numDetectionsBeforePass = finalDetections.length;

    finalDetections = finalDetections.filter(tech => {
      const meta = tech._meta;
      if (!meta) return true;

      if (meta.requires) {
        const reqs = Array.isArray(meta.requires) ? meta.requires : [meta.requires];
        if (!reqs.every(reqName => currentDetectionNames.has(reqName.split('\\;')[0]))) {
          return false;
        }
      }
      if (meta.requiresCategory) {
        const reqCats = Array.isArray(meta.requiresCategory) ? meta.requiresCategory : [meta.requiresCategory];
        if (!reqCats.some(reqCatName =>
          finalDetections.some(d => (d.category === reqCatName || d.categories?.includes(reqCatName)) && d.technology !== tech.technology)
        )) {
          return false;
        }
      }
      return true;
    });
    if (finalDetections.length !== numDetectionsBeforePass && !changedInPass) changedInPass = true;


    detectedTechMap = new Map(finalDetections.map(t => [t.technology, t]));
    const currentActiveTechNames = new Set(finalDetections.map(t => t.technology));

    const excludedTechNamesThisPass = new Set<string>();
    for (const tech of finalDetections) {
      const meta = tech._meta;
      if (meta?.excludes) {
        const exclusions = Array.isArray(meta.excludes) ? meta.excludes : [meta.excludes];
        exclusions.forEach(exNamePattern => {
          const exName = exNamePattern.split('\\;')[0];
          if (currentActiveTechNames.has(exName)) {
            const techToExclude = finalDetections.find(t => t.technology === exName);
            const excludingTech = tech;
            if (excludingTech.confidence >= techToExclude.confidence * 0.9) { 
                 excludedTechNamesThisPass.add(exName);
            }
          }
        });
      }
    }
    const preExclusionCount = finalDetections.length;
    if (excludedTechNamesThisPass.size > 0) {
        finalDetections = finalDetections.filter(tech => !excludedTechNamesThisPass.has(tech.technology));
        if (finalDetections.length !== preExclusionCount && !changedInPass) changedInPass = true;
    }
    
    detectedTechMap = new Map(finalDetections.map(t => [t.technology, t]));

    let newImpliesMadeThisSubIteration;
    do {
        newImpliesMadeThisSubIteration = false;
        for (const tech of Array.from(detectedTechMap.values())) { 
            const meta = tech._meta;
            if (meta?.implies) {
                const implications = Array.isArray(meta.implies) ? meta.implies : [meta.implies];
                implications.forEach(impliedPattern => {
                    const impliedName = impliedPattern.split('\\;')[0];
                    let impliedConfidenceOverride: number | undefined;
                    if (impliedPattern.includes('confidence:')) {
                        impliedConfidenceOverride = parseInt(impliedPattern.split('confidence:')[1], 10);
                    }

                    if (!detectedTechMap.has(impliedName)) {
                        let impliedSigDef: SignatureDefinition | undefined;
                        let impliedCategoryKey: string | undefined;

                        for (const catKey in precompiledSignatures) {
                            if (precompiledSignatures[catKey as keyof SignaturesDatabase][impliedName]) {
                                impliedSigDef = precompiledSignatures[catKey as keyof SignaturesDatabase][impliedName];
                                impliedCategoryKey = catKey;
                                break;
                            }
                        }

                        if (impliedSigDef && impliedCategoryKey) {
                            const impliedBaseConf = impliedSigDef._weight !== undefined ? impliedSigDef._weight * 100 : 30;
                            let finalImpliedConfidence = impliedBaseConf;
                            if (impliedConfidenceOverride !== undefined) {
                                finalImpliedConfidence = impliedConfidenceOverride;
                            } else {
                                finalImpliedConfidence = Math.min(100, Math.round(Math.max(impliedBaseConf, tech.confidence * 0.75)));
                            }
                            
                            const newImpliedTech: DetectedTechnologyInfo = {
                                technology: impliedName,
                                version: null, 
                                confidence: finalImpliedConfidence,
                                category: impliedCategoryKey,
                                categories: impliedSigDef.cats?.map(String),
                                website: impliedSigDef.website,
                                icon: impliedSigDef.icon,
                                detectionMethod: `Implied by ${tech.technology}`,
                                _meta: { 
                                    implies: impliedSigDef.implies,
                                    excludes: impliedSigDef.excludes,
                                    requires: impliedSigDef.requires,
                                    requiresCategory: impliedSigDef.requiresCategory
                                }
                            };
                            detectedTechMap.set(impliedName, newImpliedTech); 
                            newImpliesMadeThisSubIteration = true;
                            if(!changedInPass) changedInPass = true;
                        }
                    } else {
                        const existingImplied = detectedTechMap.get(impliedName)!;
                        let newConfidence = existingImplied.confidence;
                         if (impliedConfidenceOverride !== undefined) {
                            newConfidence = Math.max(newConfidence, impliedConfidenceOverride);
                        } else {
                            newConfidence = Math.max(newConfidence, Math.min(100, Math.round(tech.confidence * 0.75)));
                        }
                        if (newConfidence > existingImplied.confidence) {
                            existingImplied.confidence = newConfidence;
                            if(!changedInPass) changedInPass = true; 
                        }
                    }
                });
            }
        }
        if(newImpliesMadeThisSubIteration) { 
            finalDetections = Array.from(detectedTechMap.values());
        }
    } while (newImpliesMadeThisSubIteration);
  } 

  const technologies = finalDetections.map(tech => {
    const { _meta, ...rest } = tech;
    return rest as DetectedTechnologyInfo;
  }).sort((a, b) => b.confidence - a.confidence || a.technology.localeCompare(b.technology)); 

  return { technologies, redFlags };
}


// Functions to manage signatures dynamically (if needed, currently not used by main flow but good for extensibility)
export function addSignature(categoryKey: keyof SignaturesDatabase, techName: string, signature: SignatureDefinition) {
  if (!precompiledSignatures[categoryKey]) {
    (precompiledSignatures[categoryKey] as Record<string, SignatureDefinition>) = {};
  }
  const tempSigContainer = { [techName]: signature };
  const tempCatContainer = { [categoryKey]: tempSigContainer } as unknown as SignaturesDatabase; 
  precompileSignatures(tempCatContainer); 

  precompiledSignatures[categoryKey][techName] = tempCatContainer[categoryKey][techName];
}

export function deleteSignatureByName(nameToDelete: string): boolean {
  let deleted = false;
  for (const categoryKey in precompiledSignatures) {
    const category = precompiledSignatures[categoryKey as keyof SignaturesDatabase];
    if (category[nameToDelete]) {
      delete category[nameToDelete];
      deleted = true;
      break; 
    }
  }
  return deleted;
}
