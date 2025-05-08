/**
 * TechDetective Pro - Technology Signatures
 *
 * This file contains the signature database for detecting web technologies.
 * Enhanced with patterns for obfuscated/minified code detection.
 */
import type { PageContentResult } from '@/services/page-retriever'; // Ensure this matches the updated interface
import { retrieveRobotsTxt } from '@/services/page-retriever';

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


// Define the structure for a single pattern within a signature
export interface Pattern {
  type: 'html' | 'script' | 'css' | 'header' | 'meta' | 'cookie' | 'jsGlobal' | 'networkRequest' | 'jsVersion' | 'htmlComment' | 'filePath' | 'robots' | 'error' | 'dom';
  pattern: RegExp | string | Record<string, any>; // RegExp for most, string for names, object for DOM
  value?: RegExp | string;          // For header value, meta content, cookie value, DOM attribute/text value
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
        // Attempt to convert to RegExp if not already (and not for specific types like js object keys)
        // This needs to be smarter based on the type
        if (typeof mainPattern === 'string' && !mainPattern.startsWith('/') && !mainPattern.endsWith('/')) {
             try { mainPattern = new RegExp(mainPattern, 'i'); } catch (e) { /* keep as string if invalid regex */ }
        }
        return { mainPattern, confidence, version };
    };


    wappalyzerPatternFields.forEach(field => {
        const fieldValue = sigDef[field as keyof SignatureDefinition] as any;
        if (!fieldValue) return;

        const wappalyzerTypeToOurType = (wappField: string): Pattern['type'] | null => {
            switch(wappField) {
                case 'cookies': return 'cookie';
                case 'dom': return 'dom'; // Special handling for DOM needed
                case 'js': return 'jsGlobal'; // Wappalyzer 'js' often refers to globals/properties
                case 'headers': return 'header';
                case 'html': return 'html';
                case 'text': return 'html'; // Assuming 'text' in Wappalyzer means plaintext in HTML
                case 'css': return 'css'; // Assuming CSS content matching
                case 'robots': return 'robots';
                case 'url': return 'filePath'; // Wappalyzer 'url' is like our filePath
                case 'xhr': return 'networkRequest'; // Matching XHR URLs
                case 'meta': return 'meta';
                case 'scriptSrc': return 'script'; // Matching script src attributes
                case 'scripts': return 'script'; // Matching script content
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
                }
            });
        } else if (typeof fieldValue === 'object') {
            // For object types like 'cookies', 'headers', 'meta', 'js', 'dom'
            Object.entries(fieldValue).forEach(([key, valuePattern]) => {
                if (typeof valuePattern === 'string') {
                    const { mainPattern: valMainPattern, confidence, version } = parsePatternString(valuePattern);
                     patterns.push({ 
                        type: ourType, 
                        pattern: key, // The key (e.g., header name, cookie name)
                        value: valMainPattern, // The pattern for the value
                        weight: confidence ? confidence / 100 : undefined,
                        version 
                    });
                } else if (valuePattern instanceof RegExp) {
                     patterns.push({ type: ourType, pattern: key, value: valuePattern });
                } else if (ourType === 'dom' && typeof valuePattern === 'object') {
                    // Specific DOM structure
                    patterns.push({ type: 'dom', pattern: key, value: valuePattern as any });
                }
            });
        }
    });
    return patterns;
}


// Function to transform the imported Wappalyzer-like structure
function transformSignatures<T extends Record<string, SignatureDefinition>>(
  categorySignatures: T,
  categoryName: string // Added categoryName for debugging and context
): Record<string, SignatureDefinition> {
  const transformed: Record<string, SignatureDefinition> = {};
  for (const techName in categorySignatures) {
    const originalSig = categorySignatures[techName];
    transformed[techName] = {
      name: techName, // Ensure name is part of the object
      ...originalSig,
      _normalizedPatterns: normalizeWappalyzerPatterns(originalSig),
      _weight: originalSig._weight || 0.5 // Default base weight if not specified
    };
    // If original 'patterns' or 'versions' exist (our old format), merge or prioritize
    if (originalSig.patterns) {
        transformed[techName]._normalizedPatterns = [
            ...(transformed[techName]._normalizedPatterns || []),
            ...originalSig.patterns!
        ];
    }
     // Note: Version transformation from Wappalyzer format is more complex and not fully implemented here.
     // This example prioritizes the '_normalizedPatterns' from Wappalyzer fields.
  }
  return transformed;
}

const signatures: SignaturesDatabase = {
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
          if (typeof p.pattern === 'string' && 
              p.type !== 'header' && p.type !== 'meta' && 
              p.type !== 'cookie' && p.type !== 'jsGlobal' && 
              p.type !== 'dom' /* DOM pattern can be selector string */) {
            try { p.pattern = new RegExp(p.pattern.replace(/\\\\/g, '\\'), 'i'); } // Handle double escapes for regex in JSON
            catch (e) { console.warn(`Invalid regex string for p.pattern '${p.pattern}' for ${sig.name}: ${p.type}`, e); }
          }
          // Compile p.value if it's a string meant to be a regex
          if (p.value && typeof p.value === 'string') {
            try { p.value = new RegExp(p.value.replace(/\\\\/g, '\\'), 'i'); } 
            catch (e) { console.warn(`Invalid regex string for p.value '${p.value}' for ${sig.name}: ${p.type} - ${p.pattern}`, e); }
          }
        });
      };
      compileList(sig._normalizedPatterns);
      // Also compile original patterns/versions if they exist and are used (our old format)
      compileList(sig.patterns); 
      if (sig.versions) {
        compileList(sig.versions.patterns);
        for (const versionName in sig.versions) {
          if (versionName === 'patterns' || versionName === 'versionProperty') continue;
          const versionDef = sig.versions[versionName];
          if (Array.isArray(versionDef)) {
            compileList(versionDef);
          } else if (versionDef.patterns) {
            compileList(versionDef.patterns);
          }
        }
      }
    }
  }
  return sigDb;
}

const precompiledSignatures = precompileSignatures(JSON.parse(JSON.stringify(signatures)));

export interface DetectedTechnologyInfo {
  id?: string;
  technology: string;
  version: string | null;
  confidence: number; // 0-100
  isHarmful?: boolean;
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
      // Example: "session_id=abc; Path=/; HttpOnly" -> name: session_id, value: abc
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
  const globalRegex = /(?:var|let|const|window)\s*([a-zA-Z_$][\w$]*)\s*(?:=|\(|\[|\.)|(?:^|\W)([a-zA-Z_$][\w$]*)\s*=\s*(?:\{|function|\(|new\s)/g;
  let match;
  while ((match = globalRegex.exec(html)) !== null) {
    globals.add(match[1] || match[2]);
  }
  const commonLibs = ['React', 'ReactDOM', 'Vue', 'jQuery', '$', '_', 'angular', 'WPCOMGlobal', 'Shopify', 'gtag', 'ga', 'mixpanel', 'dataLayer', 'webpackJsonp', '__webpack_require__', 'OneTrust', 'Optanon', 'Stripe', 'paypal', 'bitpay', 'wp'];
  commonLibs.forEach(lib => {
    if (new RegExp(`\\b${lib.replace('$', '\\$')}\\b`).test(html)) {
      globals.add(lib);
    }
  });
  return Array.from(globals);
};

const extractNetworkRequests = (html: string, scriptsSrc: string[], cssLinks: string[]): string[] => {
    const requests = new Set<string>();
    if (html) {
      const urlRegex = /(['"`])(https?:\/\/[^'"`\s]+)\1/g;
      let match;
      while ((match = urlRegex.exec(html)) !== null) {
          requests.add(match[2]);
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
  let confidenceFactor = patternDef.weight !== undefined ? patternDef.weight : 1.0; // Default from pattern

  // Wappalyzer-style confidence and version extraction from pattern string itself
  if (patternDef.confidence) { // e.g. ";confidence:50" parsed into patternDef.confidence string
      const confValue = parseInt(patternDef.confidence.split(':')[1], 10);
      if (!isNaN(confValue)) confidenceFactor = confValue / 100;
  }
  if (patternDef.version) { // e.g. ";version:\\1"
      // Version extraction logic will use this later with regex exec result
  }

  const testRegex = (textToTest: string | undefined, regex: RegExp, versionTemplate?: string, versionGroup?: number) => {
    if (typeof textToTest !== 'string') return;
    const execResult = regex.exec(textToTest);
    if (execResult) {
      match = true;
      matchedString = execResult[0]; 
      if (versionTemplate) { // Wappalyzer style like \\1 or \\1?foo:bar
          version = resolveVersionTemplate(versionTemplate, execResult);
      } else if (versionGroup && execResult[versionGroup]) {
        version = execResult[versionGroup];
      }
    }
  };
  
  const testString = (textToTest: string | undefined, str: string) => {
     if (typeof textToTest === 'string' && textToTest.toLowerCase().includes(str.toLowerCase())) {
         match = true;
         matchedString = str; 
     }
  };

  // Wappalyzer-style version template resolution
  const resolveVersionTemplate = (template: string, execResult: RegExpExecArray): string | null => {
    // Example: \\1?foo:bar or \\1
    // This is a simplified resolver. Wappalyzer's is more complex.
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
      const headerKey = (patternDef.pattern as string).toLowerCase(); 
      const headerVal = responseHeaders[headerKey];
      if (headerVal) {
        const headerValStr = Array.isArray(headerVal) ? headerVal.join(', ') : headerVal;
        if (patternDef.value instanceof RegExp) {
          testRegex(headerValStr, patternDef.value, patternDef.version, patternDef.versionCaptureGroup);
        } else if (typeof patternDef.value === 'string') {
          if(headerValStr.toLowerCase().includes(patternDef.value.toLowerCase())) {
              match = true;
              matchedString = `${headerKey}: ${patternDef.value}`;
          }
        } else { 
          match = true;
          matchedString = headerKey;
        }
      }
      break;
    case 'meta':
      const metaKey = (patternDef.pattern as string).toLowerCase(); 
      if (extractedMetaTags[metaKey]) {
        if (patternDef.value instanceof RegExp) { 
          testRegex(extractedMetaTags[metaKey], patternDef.value, patternDef.version, patternDef.versionCaptureGroup);
        } else if (typeof patternDef.value === 'string') {
           if(extractedMetaTags[metaKey].toLowerCase().includes(patternDef.value.toLowerCase())){
               match = true;
               matchedString = `${metaKey}=${patternDef.value}`;
           }
        } else if (typeof patternDef.value === 'undefined') { 
          match = true;
          matchedString = metaKey;
        }
      }
      break;
    case 'cookie':
        parsedCookies.forEach(cookie => {
            let nameMatches = false;
            if (patternDef.pattern instanceof RegExp) {
                if (patternDef.pattern.test(cookie.name)) nameMatches = true;
            } else if (typeof patternDef.pattern === 'string' && cookie.name.toLowerCase() === patternDef.pattern.toLowerCase()) {
                nameMatches = true;
            }

            if (nameMatches) {
                if (patternDef.value instanceof RegExp) { 
                    testRegex(cookie.value, patternDef.value, patternDef.version, patternDef.versionCaptureGroup);
                } else if (typeof patternDef.value === 'string') {
                    if(cookie.value.toLowerCase().includes(patternDef.value.toLowerCase())){
                        match = true;
                        matchedString = `${cookie.name}=${patternDef.value}`;
                    }
                } else { 
                    match = true;
                    matchedString = cookie.name;
                }
            }
        });
        break;
    case 'jsGlobal': 
      const globalName = patternDef.pattern as string;
      if (extractedJsGlobals.some(g => g === globalName || (g && g.startsWith(globalName + ".")) ) ) { 
        match = true;
        matchedString = globalName;
        // Version detection for JS globals often needs specific logic or Wappalyzer's 'js' field with value patterns
        if (patternDef.value instanceof RegExp && javaScriptVersions[globalName]) { // Assuming versionProperty for jsGlobal is the globalName itself
             testRegex(javaScriptVersions[globalName], patternDef.value, patternDef.version, patternDef.versionCaptureGroup);
        }
      }
      break;
    case 'networkRequest': 
      if (patternDef.pattern instanceof RegExp) extractedNetworkRequests.forEach(req => testRegex(req, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup));
      else if (typeof patternDef.pattern === 'string') extractedNetworkRequests.forEach(req => testString(req, patternDef.pattern as string));
      break;
    case 'jsVersion': 
      if (patternDef.versionProperty && javaScriptVersions[patternDef.versionProperty]) {
        const verStr = javaScriptVersions[patternDef.versionProperty];
        if (verStr && patternDef.pattern instanceof RegExp) {
          // Here, patternDef.pattern is the regex to match against the version string.
          // patternDef.version is the Wappalyzer template like \\1
          testRegex(verStr, patternDef.pattern as RegExp, patternDef.version, patternDef.versionCaptureGroup || 1);
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
        // DOM matching requires a DOM parser (like jsdom, or client-side browser)
        // This is a placeholder. Real DOM matching is complex server-side without a browser env.
        // If htmlContent is available, you could do string matching for simple selectors.
        if (typeof patternDef.pattern === 'string' && htmlContent) { // pattern is CSS selector
            // Simplistic check: does the selector appear in the HTML?
            // This is NOT a real DOM query.
            if (htmlContent.includes(patternDef.pattern.replace(/[#.]/g, ''))) { // Basic string check
                // Further checks for attributes/text if patternDef.value is an object
                if (typeof patternDef.value === 'object' && patternDef.value !== null) {
                    const domValue = patternDef.value as {exists?: string, attributes?: Record<string, string|RegExp>, text?: string|RegExp};
                    if (domValue.exists) match = true; // Simple existence
                    // Add more complex attribute/text checks if needed, would require regex on HTML snippets
                } else {
                   match = true; // Selector string found
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
  finalUrl: string
): Promise<DetectedTechnologyInfo[]> {
  let detectedTechMap: Map<string, DetectedTechnologyInfo> = new Map();

  const { html, headers = {}, setCookieStrings, status } = pageData;

  if (!html && Object.keys(headers).length === 0) {
    console.log("[Signatures] No HTML or headers to analyze.");
    return [];
  }
  const htmlContent = html || "";

  const extractedScripts = extractScripts(htmlContent);
  const extractedCssLinks = extractCssLinks(htmlContent);
  const extractedMetaTags = extractMetaTags(htmlContent);
  const parsedCookies = extractCookies(setCookieStrings); // Use setCookieStrings
  const extractedJsGlobals = extractPotentialJsGlobals(htmlContent);
  const extractedNetworkRequests = extractNetworkRequests(htmlContent, extractedScripts.src, extractedCssLinks);
  const extractedHtmlComments = extractHtmlComments(htmlContent);
  const javaScriptVersions = extractJsVersions(htmlContent, extractedJsGlobals);
  
  let robotsContent: string | null = null;
  const needsRobotsTxt = Object.values(precompiledSignatures).some(category => 
    Object.values(category).some(sig => 
        (sig._normalizedPatterns || []).some(p => p.type === 'robots')
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
            let patternBaseWeight = baseSigConfidence / 100; // Default to tech's base weight

            // If processing patterns for a specific version (our old format)
            if (currentVersionNameForContext && sigDef.versions && sigDef.versions[currentVersionNameForContext]) {
                const versionInfo = sigDef.versions[currentVersionNameForContext];
                if (!Array.isArray(versionInfo) && versionInfo.weight !== undefined) {
                    patternBaseWeight = versionInfo.weight;
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
            if (pDef.implies) pDef.implies.forEach(imp => accumulatedImplications.add(imp));
          }
        }
      };
      
      // Process normalized patterns (from Wappalyzer fields or our _normalizedPatterns)
      processPatternsList(sigDef._normalizedPatterns);

      // Process our original `versions` object if it exists
      if (sigDef.versions) {
        const globalVersionProp = sigDef.versions.versionProperty || sigDef.versionProperty;
        if (globalVersionProp && javaScriptVersions[globalVersionProp]) {
            const currentVersion = javaScriptVersions[globalVersionProp];
            // If a global version is found, try to match it with a named version or use it directly
            let versionMatchedByName = false;
            for (const versionName in sigDef.versions) {
                 if (versionName === 'patterns' || versionName === 'versionProperty') continue;
                 if (currentVersion && versionName.includes(currentVersion.split('.')[0])) { // Simple major version match
                    const versionDetail = sigDef.versions[versionName];
                    if (Array.isArray(versionDetail)) {
                        processPatternsList(versionDetail, versionName);
                    } else {
                        processPatternsList(versionDetail.patterns, versionName);
                    }
                    if (techMatchOccurred) techDetectedVersion = techDetectedVersion || versionName; // Prioritize named version
                    versionMatchedByName = true;
                    break;
                 }
            }
            if (techMatchOccurred && !techDetectedVersion && currentVersion) { // If match but no named version, use JS version
                techDetectedVersion = currentVersion;
            }
        }
        // Process patterns within each named version definition
        for (const versionName in sigDef.versions) {
            if (versionName === 'patterns' || versionName === 'versionProperty') continue;
            const versionDetail = sigDef.versions[versionName];
            if (Array.isArray(versionDetail)) {
                processPatternsList(versionDetail, versionName);
            } else {
                processPatternsList(versionDetail.patterns, versionName);
            }
        }
        // Process fallback patterns in sigDef.versions.patterns
        if (sigDef.versions.patterns) {
            processPatternsList(sigDef.versions.patterns);
        }
      }
      
      // Process general patterns from sigDef.patterns (our old format)
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
            categories: sigDef.cats?.map(String), // Assuming cats are numbers, convert to string array
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

  // --- Post-processing Pass (Implications, Excludes, Requires) ---
  let finalDetections = Array.from(detectedTechMap.values());
  let changedInPass = true;
  let maxPasses = 5; // Prevent infinite loops
  let currentPass = 0;
  
  while(changedInPass && currentPass < maxPasses){
    changedInPass = false;
    currentPass++;
    const currentDetectionNames = new Set(finalDetections.map(t => t.technology));
    const numDetectionsBeforePass = finalDetections.length;

    // 1. Apply 'requires' and 'requiresCategory'
    finalDetections = finalDetections.filter(tech => {
      const meta = tech._meta;
      if (!meta) return true;

      if (meta.requires) {
        const reqs = Array.isArray(meta.requires) ? meta.requires : [meta.requires];
        if (!reqs.every(reqName => currentDetectionNames.has(reqName.split('\\;')[0]))) {
          console.log(`[Signatures] Removing ${tech.technology} due to missing requirement: ${reqs.find(r => !currentDetectionNames.has(r.split('\\;')[0]))}`);
          return false;
        }
      }
      if (meta.requiresCategory) {
        const reqCats = Array.isArray(meta.requiresCategory) ? meta.requiresCategory : [meta.requiresCategory];
        if (!reqCats.some(reqCatName =>
          finalDetections.some(d => (d.category === reqCatName || d.categories?.includes(reqCatName)) && d.technology !== tech.technology)
        )) {
          console.log(`[Signatures] Removing ${tech.technology} due to missing category requirement: ${reqCats.join(', ')}`);
          return false;
        }
      }
      return true;
    });
    if (finalDetections.length !== numDetectionsBeforePass && !changedInPass) changedInPass = true;


    detectedTechMap = new Map(finalDetections.map(t => [t.technology, t]));
    const currentActiveTechNames = new Set(finalDetections.map(t => t.technology));

    // 2. Apply 'excludes'
    const excludedTechNamesThisPass = new Set<string>();
    for (const tech of finalDetections) {
      const meta = tech._meta;
      if (meta?.excludes) {
        const exclusions = Array.isArray(meta.excludes) ? meta.excludes : [meta.excludes];
        exclusions.forEach(exNamePattern => {
          const exName = exNamePattern.split('\\;')[0];
          if (currentActiveTechNames.has(exName)) {
            // Find the tech to be excluded
            const techToExclude = finalDetections.find(t => t.technology === exName);
            const excludingTech = tech;
            // Simplistic: exclude if confidences are similar or excluder is higher.
            // Wappalyzer might have more nuanced logic.
            if (techToExclude && excludingTech.confidence >= techToExclude.confidence * 0.9) { // Be a bit lenient
                 console.log(`[Signatures] ${tech.technology} (conf: ${tech.confidence}) excludes ${exName} (conf: ${techToExclude.confidence}). Adding ${exName} to exclusion list.`);
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

    // 3. Apply 'implies' (iteratively within the main loop)
    let newImpliesMadeThisSubIteration;
    do {
        newImpliesMadeThisSubIteration = false;
        for (const tech of Array.from(detectedTechMap.values())) { // Iterate over current state of map
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
                            console.log(`[Signatures] ${tech.technology} implies ${impliedName}. Adding.`);
                            const impliedBaseConf = impliedSigDef._weight !== undefined ? impliedSigDef._weight * 100 : 30;
                            // Implied confidence can be: override, factor of implying tech's conf, or base implied conf
                            let finalImpliedConfidence = impliedBaseConf;
                            if (impliedConfidenceOverride !== undefined) {
                                finalImpliedConfidence = impliedConfidenceOverride;
                            } else {
                                finalImpliedConfidence = Math.min(100, Math.round(Math.max(impliedBaseConf, tech.confidence * 0.75)));
                            }
                            
                            const newImpliedTech: DetectedTechnologyInfo = {
                                technology: impliedName,
                                version: null, // Version from implies is complex, not handled here
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
                            detectedTechMap.set(impliedName, newImpliedTech); // Add to map
                            // finalDetections will be rebuilt from map after implies loop
                            newImpliesMadeThisSubIteration = true;
                            if(!changedInPass) changedInPass = true;
                        }
                    } else {
                        // Implied tech already exists, potentially update confidence
                        const existingImplied = detectedTechMap.get(impliedName)!;
                        let newConfidence = existingImplied.confidence;
                         if (impliedConfidenceOverride !== undefined) {
                            newConfidence = Math.max(newConfidence, impliedConfidenceOverride);
                        } else {
                            newConfidence = Math.max(newConfidence, Math.min(100, Math.round(tech.confidence * 0.75)));
                        }
                        if (newConfidence > existingImplied.confidence) {
                            existingImplied.confidence = newConfidence;
                            if(!changedInPass) changedInPass = true; // Confidence update counts as a change
                        }
                    }
                });
            }
        }
        if(newImpliesMadeThisSubIteration) { // If implies added new techs, rebuild finalDetections for next pass
            finalDetections = Array.from(detectedTechMap.values());
        }
    } while (newImpliesMadeThisSubIteration);
  } 

  return finalDetections.map(tech => {
    const { _meta, ...rest } = tech;
    return rest as DetectedTechnologyInfo;
  }).sort((a, b) => b.confidence - a.confidence || a.technology.localeCompare(b.technology)); 
}


// Functions to manage signatures dynamically (if needed, currently not used by main flow but good for extensibility)
export function addSignature(category: keyof SignaturesDatabase, techName: string, signature: SignatureDefinition) {
  if (!precompiledSignatures[category]) {
    (precompiledSignatures[category] as Record<string, SignatureDefinition>) = {};
  }
  // Precompile the new signature before adding
  const tempSigContainer = { [techName]: signature };
  const tempCatContainer = { [category]: tempSigContainer } as unknown as SignaturesDatabase; 
  precompileSignatures(tempCatContainer); // This will modify signature in tempSigContainer

  precompiledSignatures[category][techName] = tempSigContainer[techName];
  console.log(`[Signatures] Added signature "${techName}" to category "${category}".`);
}

export function deleteSignatureByName(nameToDelete: string): boolean {
  let deleted = false;
  for (const categoryKey in precompiledSignatures) {
    const category = precompiledSignatures[categoryKey as keyof SignaturesDatabase];
    if (category[nameToDelete]) {
      delete category[nameToDelete];
      deleted = true;
      console.log(`[Signatures] Deleted signature "${nameToDelete}" from category "${categoryKey}".`);
      break; 
    }
  }
  if (!deleted) {
    console.log(`[Signatures] Signature "${nameToDelete}" not found for deletion.`);
  }
  return deleted;
}
