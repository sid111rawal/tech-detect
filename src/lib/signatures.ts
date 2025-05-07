// src/lib/signatures.ts

export interface TechnologySignature {
  id: string; // Unique ID for the signature
  name: string;
  category: string; // e.g., "JavaScript Framework", "Analytics", "CMS", "UI Library", "CDN", "Web Server", "Programming Language"
  type: 'scriptSrc' | 'globalVarPattern' | 'metaTag' | 'htmlContent' | 'headerValue' | 'cookieName' | 'cssClass' | 'htmlComment' | 'filePath';
  pattern: RegExp;
  versionCaptureGroup?: number; // Index of the RegExp capture group for version extraction
  confidence: number; // Base confidence (0.0 to 1.0)
  website?: string; // Official website of the technology
  implies?: string[]; // Names of other technologies implied by this one
  description?: string; // Explanation of how this signature helps identify the technology
  // For 'headerValue' type:
  headerName?: string; // Specific header to check (e.g., 'Server', 'X-Powered-By')
}

export interface DetectedTechnologyInfo {
  id: string; // Corresponds to TechnologySignature id that led to detection
  name: string;
  version?: string;
  confidence: number;
  category: string;
  detectionMethod: string; // Describes how it was detected (e.g., "Signature: React (scriptSrc)")
  matchedValue?: string; // The actual string value that matched the pattern
  website?: string;
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

function extractMetaTags(html: string): { name?: string; property?: string; content: string }[] {
  const metaRegex = /<meta\s+(?=[^>]*content=(['"])([^>]*?)\1)(?:[^>]*name=(['"])([^>]*?)\3|[^>]*property=(['"])([^>]*?)\5)?[^>]*>/gi;
  const tags: { name?: string; property?: string; content: string }[] = [];
  let match;
  while ((match = metaRegex.exec(html)) !== null) {
    const content = match[2];
    const name = match[4];
    const property = match[6];
    if (content) {
      tags.push({ name: name?.toLowerCase(), property: property?.toLowerCase(), content });
    }
  }
  return tags;
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
    const classRegex = /class=["']([^"']+)["']/gi;
    const classes = new Set<string>();
    let match;
    while((match = classRegex.exec(html)) !== null) {
        match[1].split(/\s+/).forEach(cls => cls && classes.add(cls));
    }
    // Also look for classes in SVG elements
    const svgClassRegex = /class=["']([^"']+)["']/gi;
    while((match = svgClassRegex.exec(html)) !== null) {
        match[1].split(/\s+/).forEach(cls => cls && classes.add(cls));
    }
    return Array.from(classes);
}

// --- Signatures Database (Examples) ---
// This database needs to be significantly expanded for comprehensive detection.
export const signaturesDb: TechnologySignature[] = [
  // JavaScript Frameworks & Libraries
  {
    id: 'react_js_src', name: 'React', category: 'JavaScript Framework', type: 'scriptSrc',
    pattern: /react(?:-dom)?(?:\.\d+\.\d+(?:\.\d+)?)?(?:\.development|\.production\.min)?\.js$/i, confidence: 0.85, website: 'https://reactjs.org/',
    description: 'Detects React by common script filenames like react.js or react-dom.js.'
  },
  {
    id: 'react_dev_tools_hook', name: 'React', category: 'JavaScript Framework', type: 'htmlContent',
    pattern: /__REACT_DEVTOOLS_GLOBAL_HOOK__/i, confidence: 0.7, website: 'https://reactjs.org/',
    description: 'Detects React Developer Tools global hook, often present in development or non-minified builds.'
  },
  {
    id: 'react_data_root_attr', name: 'React', category: 'JavaScript Framework', type: 'htmlContent',
    pattern: /data-reactroot/i, confidence: 0.65, website: 'https://reactjs.org/',
    description: 'Detects the data-reactroot attribute commonly added by older React versions to the root HTML element.'
  },
  {
    id: 'jquery_js_src_versioned', name: 'jQuery', category: 'JavaScript Library', type: 'scriptSrc',
    pattern: /jquery-([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?)(?:\.min|\.slim|\.slim\.min)?\.js$/i, versionCaptureGroup: 1, confidence: 0.95, website: 'https://jquery.com/',
    description: 'Detects jQuery script file with version in the filename.'
  },
  {
    id: 'jquery_js_src_unversioned', name: 'jQuery', category: 'JavaScript Library', type: 'scriptSrc',
    pattern: /jquery(?:\.min|\.slim|\.slim\.min)?\.js$/i, confidence: 0.8, website: 'https://jquery.com/',
    description: 'Detects jQuery script file without version in the filename.'
  },
  {
    id: 'vue_js_src', name: 'Vue.js', category: 'JavaScript Framework', type: 'scriptSrc',
    pattern: /vue(?:\.runtime|\.common)?(?:\.esm-browser|\.global)?(?:\.\d+\.\d+(?:\.\d+)?)?(?:\.min|\.prod)?\.js$/i, confidence: 0.85, website: 'https://vuejs.org/',
    description: 'Detects Vue.js by common script filenames.'
  },
  {
    id: 'vue_data_v_app_attr', name: 'Vue.js', category: 'JavaScript Framework', type: 'htmlContent',
    pattern: /data-v-app/i, confidence: 0.75, website: 'https://vuejs.org/',
    description: 'Detects Vue.js specific `data-v-app` attribute on elements.'
  },
  {
    id: 'angularjs_1_src', name: 'AngularJS', category: 'JavaScript Framework', type: 'scriptSrc', // Legacy AngularJS (1.x)
    pattern: /angular(?:\.min)?\.js/i, confidence: 0.8, website: 'https://angularjs.org/',
    description: 'Detects AngularJS (1.x) script file.'
  },
  {
    id: 'angular_modern_version_attr', name: 'Angular', category: 'JavaScript Framework', type: 'htmlContent', // Modern Angular (2+)
    pattern: /ng-version="([0-9]+\.[0-9]+\.[0-9]+[^"]*)"/i, versionCaptureGroup: 1, confidence: 0.9, website: 'https://angular.io/',
    description: 'Detects Angular (2+) ng-version attribute in HTML and extracts version.'
  },
  {
    id: 'nextjs_data_next_app_attr', name: 'Next.js', category: 'JavaScript Framework', type: 'htmlContent',
    pattern: /data-next-app|__NEXT_DATA__/i, confidence: 0.9, website: 'https://nextjs.org/',
    description: 'Detects Next.js through `data-next-app` attribute or `__NEXT_DATA__` script content.'
  },
  {
    id: 'svelte_component_marker', name: 'Svelte', category: 'JavaScript Framework', type: 'htmlComment',
    pattern: /SVELTE_HYDRATER COMMENT/i, confidence: 0.7, website: 'https://svelte.dev/',
    description: 'Detects Svelte hydration markers in HTML comments (less common in prod).'
  },
  {
    id: 'svelte_css_class_pattern', name: 'Svelte', category: 'JavaScript Framework', type: 'cssClass',
    pattern: /^svelte-[a-z0-9]+$/i, confidence: 0.6, website: 'https://svelte.dev/',
    description: 'Detects Svelte by its typical generated CSS class pattern (e.g., svelte-123xyz).'
  },

  // Analytics
  {
    id: 'ga_gtag_src', name: 'Google Analytics (gtag.js)', category: 'Analytics', type: 'scriptSrc',
    pattern: /googletagmanager\.com\/gtag\/js\?id=(UA-|G-|AW-|DC-)[A-Z0-9-]+/i, versionCaptureGroup: 1, confidence: 0.95, website: 'https://analytics.google.com/',
    description: 'Detects Google Analytics (gtag.js) script and captures ID prefix.'
  },
  {
    id: 'ga_universal_src', name: 'Google Analytics (Universal)', category: 'Analytics', type: 'scriptSrc',
    pattern: /google-analytics\.com\/analytics\.js/i, confidence: 0.9, website: 'https://analytics.google.com/',
    description: 'Detects Google Analytics (Universal Analytics - analytics.js) script.'
  },
  {
    id: 'hotjar_src', name: 'Hotjar', category: 'Analytics', type: 'scriptSrc',
    pattern: /static\.hotjar\.com\/c\/hotjar-/i, confidence: 0.9, website: 'https://www.hotjar.com/',
    description: 'Detects Hotjar analytics script.'
  },

  // CMS
  {
    id: 'wordpress_meta_generator', name: 'WordPress', category: 'CMS', type: 'metaTag',
    pattern: /WordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9.]+)?)/i, versionCaptureGroup: 1, confidence: 0.98, website: 'https://wordpress.org/',
    description: 'Detects WordPress via meta generator tag and extracts version.'
  },
  {
    id: 'wordpress_body_classes', name: 'WordPress', category: 'CMS', type: 'cssClass',
    pattern: /^(wp-block-|logged-in|admin-bar|home|blog|archive|author|category-|tag-|page-template-|postid-|single-|search-results)/i, confidence: 0.7,
    description: 'Detects WordPress by common body CSS classes. Moderate confidence due to potential reuse.'
  },
  {
    id: 'wordpress_filepaths', name: 'WordPress', category: 'CMS', type: 'filePath',
    pattern: /\/wp-(?:content|includes|admin)\//i, confidence: 0.85,
    description: 'Detects WordPress by common file path structures in script/link tags.'
  },
  {
    id: 'joomla_meta_generator', name: 'Joomla', category: 'CMS', type: 'metaTag',
    pattern: /Joomla!/i, confidence: 0.95, website: 'https://www.joomla.org/',
    description: 'Detects Joomla via meta generator tag.'
  },
  {
    id: 'drupal_meta_generator', name: 'Drupal', category: 'CMS', type: 'metaTag',
    pattern: /Drupal\s*([0-9]+)/i, versionCaptureGroup: 1, confidence: 0.95, website: 'https://www.drupal.org/',
    description: 'Detects Drupal via meta generator tag and extracts major version.'
  },
  {
    id: 'shopify_cdn_src', name: 'Shopify', category: 'CMS', type: 'scriptSrc',
    pattern: /cdn\.shopify\.com/i, confidence: 0.9, website: 'https://www.shopify.com/',
    description: 'Detects Shopify by usage of its CDN for assets.'
  },

  // UI Frameworks
  {
    id: 'bootstrap_css_link_or_src', name: 'Bootstrap', category: 'UI Framework', type: 'filePath', // Matches in <link href> or <script src>
    pattern: /bootstrap(?:\.min)?\.(css|js)/i, confidence: 0.8, website: 'https://getbootstrap.com/',
    description: 'Detects Bootstrap CSS or JS file names.'
  },
  {
    id: 'bootstrap_class_prefixes', name: 'Bootstrap', category: 'UI Framework', type: 'cssClass',
    pattern: /^(col(?:-(?:sm|md|lg|xl|xxl))?-|row|container(?:-fluid)?|modal|btn(?:-[a-z]+)?|navbar|alert(?:-[a-z]+)?|badge|card(?:-[a-z]+)?|carousel)/i, confidence: 0.6, website: 'https://getbootstrap.com/',
    description: 'Detects Bootstrap by common CSS class prefixes. Lower confidence due to generic names potentially clashing.'
  },
  {
    id: 'tailwindcss_comment_marker', name: 'Tailwind CSS', category: 'UI Framework', type: 'htmlComment',
    pattern: /tailwindcss/i, confidence: 0.7, website: 'https://tailwindcss.com/',
    description: 'Detects Tailwind CSS if mentioned in HTML comments (e.g., by build tools or for utility classes).'
  },
  {
    id: 'materialize_css_src', name: 'Materialize CSS', category: 'UI Framework', type: 'filePath',
    pattern: /materialize(?:\.min)?\.(css|js)/i, confidence: 0.8, website: 'https://materializecss.com/',
    description: 'Detects Materialize CSS or JS files.'
  },

  // CDNs
  {
    id: 'cloudflare_cdnjs_src', name: 'Cloudflare CDN (cdnjs)', category: 'CDN', type: 'scriptSrc',
    pattern: /cdnjs\.cloudflare\.com/i, confidence: 0.8, website: 'https://www.cloudflare.com/cdnjs/',
    description: 'Detects usage of Cloudflare cdnjs for hosting libraries.'
  },
  {
    id: 'google_apis_cdn_src', name: 'Google Hosted Libraries', category: 'CDN', type: 'scriptSrc',
    pattern: /ajax\.googleapis\.com/i, confidence: 0.8, website: 'https://developers.google.com/speed/libraries',
    description: 'Detects usage of Google Hosted Libraries CDN for common JS libraries.'
  },
  {
    id: 'jsdelivr_cdn_src', name: 'jsDelivr CDN', category: 'CDN', type: 'scriptSrc',
    pattern: /cdn\.jsdelivr\.net/i, confidence: 0.8, website: 'https://www.jsdelivr.com/',
    description: 'Detects usage of jsDelivr CDN.'
  },
  {
    id: 'unpkg_cdn_src', name: 'unpkg CDN', category: 'CDN', type: 'scriptSrc',
    pattern: /unpkg\.com/i, confidence: 0.8, website: 'https://unpkg.com/',
    description: 'Detects usage of unpkg CDN.'
  },
];

// --- Main Detection Function ---
export interface DetectionInput {
  htmlContent: string;
  // Future enhancements:
  // headers?: Record<string, string | string[]>;
  // cookies?: Record<string, string>;
  // url?: string; // The analyzed URL itself, for filePath patterns relative to domain
}

export function detectWithSignatures(input: DetectionInput): DetectedTechnologyInfo[] {
  const detectedMap = new Map<string, DetectedTechnologyInfo>();

  const scriptSrcs = extractScriptSrcs(input.htmlContent); // Also used for 'filePath' type
  const metaTagObjects = extractMetaTags(input.htmlContent);
  const comments = extractHtmlComments(input.htmlContent);
  const cssClasses = extractCssClasses(input.htmlContent);

  signaturesDb.forEach(sig => {
    let match: RegExpExecArray | null = null;
    let matchedValue: string | undefined;

    try {
      switch (sig.type) {
        case 'scriptSrc':
        case 'filePath': // filePath patterns check against scriptSrcs and linkHrefs (currently linkHrefs not separately extracted)
          for (const src of scriptSrcs) { // TODO: also extract and check <link href="">
            match = sig.pattern.exec(src);
            if (match) { matchedValue = src; break; }
          }
          break;
        case 'metaTag':
          for (const tag of metaTagObjects) {
            // Check against name or property for the tag identifier, and content for the value
            const targetValue = tag.name === sig.pattern.source || (tag.property && tag.property === sig.pattern.source) ? tag.name || tag.property : tag.content;
            if (tag.name && sig.pattern.test(tag.name)) { // e.g. <meta name="generator" ...> pattern: /generator/
                 match = sig.pattern.exec(tag.content); // version capture usually in content
                 if (match) matchedValue = `meta name="${tag.name}" content="${tag.content}"`;
            } else if (tag.property && sig.pattern.test(tag.property)) { // e.g. <meta property="og:type" ...> pattern: /og:type/
                 match = sig.pattern.exec(tag.content);
                 if (match) matchedValue = `meta property="${tag.property}" content="${tag.content}"`;
            } else if (sig.pattern.test(tag.content)) { // pattern directly matches content
                 match = sig.pattern.exec(tag.content);
                 if (match) matchedValue = `meta content="${tag.content}" (name: ${tag.name}, property: ${tag.property})`;
            }
            if (match) break;
          }
           // More flexible meta tag matching based on content only for 'generator' for now
           if (!match) {
                for (const tag of metaTagObjects) {
                    if (tag.name === 'generator' || tag.property === 'generator') {
                         match = sig.pattern.exec(tag.content);
                         if (match) {
                            matchedValue = `meta ${tag.name ? `name="${tag.name}"` : `property="${tag.property}"`} content="${tag.content}"`;
                            break;
                         }
                    }
                }
           }
          break;
        case 'htmlContent':
          match = sig.pattern.exec(input.htmlContent);
          if (match) matchedValue = match[0]; // The full matched string
          break;
        case 'htmlComment':
            for(const comment of comments) {
                match = sig.pattern.exec(comment);
                if (match) { matchedValue = `comment: "${comment.substring(0, 50)}..."`; break; }
            }
            break;
        case 'cssClass':
            for(const cls of cssClasses) {
                match = sig.pattern.exec(cls);
                if (match) { matchedValue = `class: "${cls}"`; break; }
            }
            break;
        // Implement headerValue, cookieName, globalVarPattern if headers/cookies/JS execution are available
        case 'globalVarPattern': // Placeholder for future JS execution environment
        case 'headerValue':      // Placeholder for future header analysis
        case 'cookieName':       // Placeholder for future cookie analysis
          break;
      }
    } catch (e) {
        console.warn(`[Signatures] Error evaluating signature ${sig.id} (${sig.name}) pattern ${sig.pattern}:`, e);
    }


    if (match) {
      const version = sig.versionCaptureGroup && match[sig.versionCaptureGroup] ? match[sig.versionCaptureGroup].trim() : undefined;
      const existing = detectedMap.get(sig.name);

      // Prioritize more confident or versioned detections
      const currentConfidence = sig.confidence + (version ? 0.1 : 0); // Slight boost for versioned finds

      if (!existing || currentConfidence > existing.confidence || (currentConfidence === existing.confidence && version && !existing.version)) {
        detectedMap.set(sig.name, {
          id: sig.id,
          name: sig.name,
          version: version || existing?.version, // Keep existing version if new one isn't found but is same tech
          confidence: Math.min(1.0, currentConfidence), // Cap confidence at 1.0
          category: sig.category,
          detectionMethod: `Signature: ${sig.name} (${sig.type})`,
          matchedValue: matchedValue,
          website: sig.website,
        });
      }
    }
  });

  return Array.from(detectedMap.values());
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
