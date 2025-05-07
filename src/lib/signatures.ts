/**
 * TechDetective Pro - Technology Signatures
 * 
 * This file contains the signature database for detecting web technologies.
 * Enhanced with patterns for obfuscated/minified code detection.
 */

const signatures = {
  // Analytics
  analytics: [
    {
      name: "Google Analytics",
      versions: {
        "Universal Analytics": {
          weight: 0.9,
          patterns: [ // Universal Analytics patterns
            { type: "script", pattern: /www\.google-analytics\.com\/analytics\.js/i, weight: 0.9 }, // Main UA script
            { type: "script", pattern: /www\.googletagmanager\.com\/gtag\/js/i, weight: 0.8 }, // Gtag script (can be used by both UA and GA4)
            { type: "cookie", pattern: /^_gid/, weight: 0.7 }, // Secondary GA cookie
            { type: "cookie", pattern: /^_gat/, weight: 0.6 }, // Throttle cookie
            { type: "jsGlobal", pattern: "ga", weight: 0.8 }, // Global function
            { type: "jsGlobal", pattern: "gtag" },
            { type: "jsGlobal", pattern: "dataLayer" },
            // Obfuscated patterns
            { type: "html", pattern: /function\s*\(\s*[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\s*\)\s*\{\s*[a-z]\s*\.\s*[a-z]\s*=\s*[a-z]\s*\.\s*[a-z]*\|\|\s*\[\]/i, weight: 0.7 },
            { type: "networkRequest", pattern: /collect\?v=1&_v=j\d+&/i }
          ]
        },
        "GA4": {
          weight: 0.95,
          patterns: [ // GA4 patterns
            { type: "script", pattern: /www\.googletagmanager\.com\/gtag\/js\?id=G-/i, weight: 0.95 }, // GA4 script
            { type: "jsGlobal", pattern: "gtag" },
            { type: "networkRequest", pattern: /\/g\/collect\?v=2/i }
          ]
        }
      }
    },
    {
      name: "Mixpanel",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /cdn\.mxpnl\.com\/libs\/mixpanel/i },
        { type: "script", pattern: /cdn\.mixpanel\.com\/mixpanel/i },
        { type: "cookie", pattern: /^mp_/ },
        { type: "jsGlobal", pattern: "mixpanel" },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /api\/2\.0\/track/i },
        { type: "html", pattern: /function\s*\(\s*[a-z]\s*\)\s*\{\s*return\s*[a-z]\s*\.\s*[a-z]+\s*\(\s*"mixpanel"\s*\)/i, weight: 0.7 }
      ]
    },
    {
      name: "Segment",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /cdn\.segment\.com\/analytics\.js/i },
        { type: "cookie", pattern: /^ajs_/ },
        { type: "jsGlobal", pattern: "analytics" },
        { type: "networkRequest", pattern: /api\.segment\.io\/v1/i },
        // Obfuscated patterns
        { type: "html", pattern: /window\.analytics\s*=\s*window\.analytics\s*\|\|\s*\[\]/i, weight: 0.8 }
      ]
    },
    {
      name: "Zipkin",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /zipkin/i },
        { type: "header", pattern: "x-b3-traceid" },
        { type: "header", pattern: "x-b3-spanid" },
        { type: "header", pattern: "x-b3-sampled" },
        { type: "networkRequest", pattern: /api\/v2\/spans/i },
        { type: "html", pattern: /zipkin/i }
      ]
    }
  ],

  // Utility Libraries
  utility_libraries: [
    {
      name: "jQuery",
      versions: {
        versionProperty: "$.fn.jquery",
        "jQuery 1.x": {
          weight: 0.9,
          patterns: [
            // Detects jQuery 1.x versions using the $().jquery property
            { type: "jsVersion", pattern: /^1\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-1\./i, weight: 0.8 }, // Fallback to script tag
          ]
        },
        "jQuery 2.x": {
          weight: 0.9,
          patterns: [
            // Detects jQuery 2.x versions using the $().jquery property
            { type: "jsVersion", pattern: /^2\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-2\./i, weight: 0.8 }, // Fallback to script tag
          ]
        },
        "jQuery 3.x": {
          weight: 0.9,
          patterns: [
            // Detects jQuery 3.x versions using the $().jquery property
            { type: "jsVersion", pattern: /^3\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-3\./i, weight: 0.8 }, // Fallback to script tag
          ]
        },
        "jQuery Unspecified Version": { // For cases where version property isn't detected
          weight: 0.8,
          patterns: [
          ]
        },
        patterns: [
          { type: "jsGlobal", pattern: "jQuery", weight: 0.9 },
          { type: "jsGlobal", pattern: "$", weight: 0.9 },
          { type: "script", pattern: /jquery(\.min)?\.js/i, weight: 0.8 },
          { type: "html", pattern: /<script[^>]+jquery/i },
          { type: "html", pattern: /<script[^>]+jquery-migrate/i },
        ]
      },
      versionProperty: "$.fn.jquery",
    },
    {
      name: "Lodash",
      weight: 0.9,
      patterns: [
        { type: "jsGlobal", pattern: "_" },
        { type: "script", pattern: /lodash(\.min)?\.js/i }
      ]
    }
  ],

  // Payment Processors
  payment_processors: [
    {
      name: "Stripe",
      weight: 0.95,
      patterns: [
        { type: "script", pattern: /js\.stripe\.com/i, weight: 0.9 },
        { type: "cookie", pattern: /__stripe_mid/, weight: 0.7 },
        { type: "cookie", pattern: /__stripe_sid/, weight: 0.7 },
        { type: "jsGlobal", pattern: "Stripe", weight: 0.9 },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /api\.stripe\.com/i, weight: 0.8 },
        { type: "html", pattern: /data-stripe/i, weight: 0.7 }
      ]
    },
    {
      name: "PayPal",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /paypal\.com\/sdk/i },
        { type: "script", pattern: /paypalobjects\.com/i },
        { type: "jsGlobal", pattern: "paypal", weight: 0.9 },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /\.paypal\.com/i, weight: 0.8 },
        { type: "html", pattern: /data-paypal/i, weight: 0.6 },
        { type: "cookie", pattern: /paypal/i, weight: 0.6 },
        { type: "html", pattern: /paypalcheckout/i, weight: 0.6 }
      ]
    },
    {
      name: "BitPay",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /bitpay\.com\/bitpay\.js/i },
        { type: "script", pattern: /bitpay\.com\/bitpay\.min\.js/i },
        { type: "html", pattern: /data-bitpay/i },
        { type: "networkRequest", pattern: /bitpay\.com\/api/i },
        { type: "jsGlobal", pattern: "bitpay" }
      ]
    }
  ],

  // Security
  security: [
    {
      name: "HSTS",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "strict-transport-security" }
      ]
    },
    {
      name: "Content Security Policy",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "content-security-policy" },
        { type: "meta", pattern: { name: "content-security-policy" } }
      ]
    }
  ],
  
  // Miscellaneous
  miscellaneous: [
    {
      name: "Open Graph",
      weight: 0.9,
      patterns: [
        { type: "meta", pattern: { name: "og:title" } },
        { type: "meta", pattern: { name: "og:type" } },
        { type: "meta", pattern: { name: "og:image" } },
        { type: "meta", pattern: { name: "og:url" } },
        { type: "html", pattern: /property=["']og:/i }
      ]
    }
  ],
  
  // Cookie Compliance
  cookie_compliance: [
    {
      name: "OneTrust",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /cdn\.cookielaw\.org/i },
        { type: "script", pattern: /optanon/i },
        { type: "cookie", pattern: /OptanonConsent/i },
        { type: "cookie", pattern: /OptanonAlertBoxClosed/i },
        { type: "jsGlobal", pattern: "OneTrust" },
        { type: "jsGlobal", pattern: "Optanon" },
        { type: "html", pattern: /onetrust/i }
      ]
    }
  ],

  self_hosted_cms: [
    {
      name: "WordPress",
      versions: {
        "Wordpress &lt; 4.0": {
          patterns: [
            { type: "meta", pattern: { name: "generator", content: /WordPress ([0-3]\.\d+(\.\d+)?)/i }, weight: 0.9 }
          ]
        },
        "Wordpress &gt;= 4.0": {
          weight: 0.9,
          patterns: [
            { type: "meta", pattern: { name: "generator", content: /WordPress ([4-9]\.\d+(\.\d+)?)/i }, weight: 0.9 }
          ]
        },
        "Wordpress &gt;= 6.0": {
          weight: 0.9,
          patterns: [
            { type: "meta", pattern: { name: "generator", content: /WordPress ([6-9]\.\d+(\.\d+)?)/i }, weight: 0.9 }
          ]
        }
      },
      patterns: [
        { type: "script", pattern: /wp-content/, weight: 0.8 }, // Common script location
        { type: "script", pattern: /wp-includes/, weight: 0.8 }, // Common script location
        { type: "cookie", pattern: /wordpress_/, weight: 0.7 }, // Common WordPress cookie prefix
        { type: "cookie", pattern: /wp-settings-\d/, weight: 0.7 }, // Common WordPress cookie prefix
        { type: "cookie", pattern: /wp-settings-/, weight: 0.7 }, // Common WordPress cookie prefix
        { type: "networkRequest", pattern: /wp-json/i }, // Obfuscated patterns
        { type: "jsGlobal", pattern: "wp" }
      ]
    },
    {
      name: "Squarespace",
      // category: "hosted_cms", // This was in user's prompt, but signatures are already categorized by top-level key
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
        { type: "cookie", pattern: /SESS/ }
      ]
    },
    {
      name: "Drupal",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /drupal\.js/i },
        { type: "html", pattern: /drupal-/i },
        { type: "html", pattern: /data-drupal/i },
        { type: "jsGlobal", pattern: /Drupal/i },
        { type: "meta", pattern: { name: "generator", content: /Drupal/i } },
        // Obfuscated patterns
        { type: "cookie", pattern: /SESS/ }
      ]
    },
    {
      name: "Joomla",
      // category: "self_hosted_cms", // Redundant
      weight: 0.8,
      patterns: [
        { type: "html", pattern: /joomla/i, weight: 0.8 },
        { type: "meta", pattern: { name: "generator", content: /Joomla!/i }, weight: 0.9 },
        { type: "script", pattern: /joomla-core/i, weight: 0.7 },
        { type: "networkRequest", pattern: /joomla/i, weight: 0.7 }
      ]
    }
  ],
  hosted_cms: [
    {
      name: "Ghost",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "x-ghost-cache-status" },
        { type: "meta", pattern: { name: "generator", content: /Ghost/i }, weight: 0.9 },
        { type: "html", pattern: /ghost/i },
        { type: "script", pattern: /ghost/i }
      ]
    }
  ],
  css_frameworks: [
    {
      name: "Bootstrap",
      // category: "css_frameworks", // Redundant
      versions: {
        "Bootstrap 3.x": {
          weight: 0.9,
          patterns: [
            // Detects Bootstrap 3.x versions using the script tag
            { type: "script", pattern: /bootstrapcdn\.com\/bootstrap\/3\./i, weight: 0.9 },
            // Detects Bootstrap 3.x versions using the css tag
            { type: "css", pattern: /bootstrapcdn\.com\/bootstrap\/3\./i, weight: 0.9 }
          ]
        },
        "Bootstrap 4.x": {
          weight: 0.9,
          patterns: [
            // Detects Bootstrap 4.x versions using the script tag
            { type: "script", pattern: /bootstrapcdn\.com\/bootstrap\/4\./i, weight: 0.9 },
            // Detects Bootstrap 4.x versions using the css tag with version in URL
            { type: "css", pattern: /bootstrap\/4\./i, weight: 0.9 },
            { type: "css", pattern: /bootstrapcdn\.com\/bootstrap\/4\./i, weight: 0.9 }
          ]
        },
        "Bootstrap 5.x": {
          weight: 0.9,
          patterns: [
            // Detects Bootstrap 5.x versions using the script tag
            { type: "script", pattern: /bootstrapcdn\.com\/bootstrap\/5\./i, weight: 0.9 },
            // Detects Bootstrap 5.x versions using the css tag with version in URL
            { type: "css", pattern: /bootstrap\/5\./i, weight: 0.9 },
            { type: "css", pattern: /bootstrapcdn\.com\/bootstrap\/5\./i, weight: 0.9 }
          ]
        },
        patterns: [
          { type: "script", pattern: /bootstrap(\.min)?\.js/i, weight: 0.8 }, // Common Bootstrap script
          { type: "css", pattern: /bootstrap(\.min)?\.css/i, weight: 0.8 }, // Common Bootstrap CSS
          { type: "html", pattern: /class="[^"]*navbar/i, weight: 0.7 }, // Common navbar class
          { type: "html", pattern: /class="[^"]*container/i, weight: 0.7 }, // Common container class
          { type: "html", pattern: /class="[^"]*row/i },
          { type: "html", pattern: /class="[^"]*col-/i },
          { type: "html", pattern: /class="[^"]*btn/i }
        ]
      }
    },
    {
      name: "Tailwind CSS",
      // category: "css_frameworks", // Redundant
      weight: 0.9,
      patterns: [
        { type: "css", pattern: /tailwind(\.min)?\.css/i },
        { type: "html", pattern: /class="[^"]*text-\w+-\d+/i },
        { type: "html", pattern: /class="[^"]*bg-\w+-\d+/i },
        { type: "html", pattern: /class="[^"]*p-\d+/i },
        { type: "html", pattern: /class="[^"]*m-\d+/i }
      ]
    }
  ],
  server_platforms: [
    {
      name: "Apache",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /apache/i, weight: 0.9 },
        { type: "header", pattern: "x-powered-by", value: /apache/i, weight: 0.7 },
        { type: "html", pattern: /Apache Web Server/, weight: 0.6 },
        { type: "error", pattern: /Apache/, weight: 0.7 }
      ]
    },  
    {
      name: "Nginx",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /nginx/i }
      ]
    },
    {
      name: "Express.js",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "x-powered-by", value: /express/i }
      ]
    }
  ],
  hosting_providers: [
    {
      name: "Cloudways",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /cloudways/i },
        { type: "networkRequest", pattern: /cloudwaysapps\.com/i },
        { type: "error", pattern: /cloudways/i }
      ]
    },
    {
      name: "Digital Ocean",
      weight: 0.7,
      patterns: [
        { type: "header", pattern: "server", value: /digitalocean/i },
        { type: "networkRequest", pattern: /digitalocean/i }
      ]
    }
  ],
  reverse_proxies: [
    {
      name: "AWS",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "x-amz-id-2" },
        { type: "header", pattern: "x-amz-cf-id" },
        { type: "networkRequest", pattern: /amazonaws\.com/i }
      ]
    },
    {
      name: "Google Cloud",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /Google Frontend/i, weight: 0.9 },
        { type: "networkRequest", pattern: /googleapis\.com/i }
      ]
    }, 
    {
      name: "Cloudflare",
      weight: 0.95, // High confidence for Cloudflare
      patterns: [
        { type: "header", pattern: "cf-ray", weight: 0.9 }, // Cloudflare's unique header
        { type: "header", pattern: "cf-cache-status", weight: 0.8 }, // Cloudflare's unique header
        { type: "header", pattern: "server", value: /cloudflare/i, weight: 0.8 }, // Cloudflare often sets the server header
        { type: "cookie", pattern: /__cfduid/, weight: 0.7 }, // Common Cloudflare cookie
        { type: "cookie", pattern: /__cf_bm/, weight: 0.7 }, // Common Cloudflare cookie
        { type: "networkRequest", pattern: /cloudflare\.com/i, weight: 0.7 }
      ]
    },
    {
      name: "Envoy",
      // category: "reverse_proxies", // Redundant
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /envoy/i },
        { type: "header", pattern: "x-envoy-upstream-service-time" }
      ]
    }
  ],
  programming_languages: [
    {
      // Check for X-Powered-By header or PHPSESSID cookie
      name: "PHP",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "x-powered-by", value: /php/i },
        { type: "cookie", pattern: /PHPSESSID/i }
      ]
    },
    {
      // Check for Phusion Passenger server header or Ruby session cookie
      name: "Ruby",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /Phusion Passenger/i },
        { type: "cookie", pattern: /_session_id/i }
      ]
    },
    {
      // Check for Python server header or Django/Flask cookies
      name: "Python",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /Python/i },
        { type: "cookie", pattern: /django_/i },
        { type: "cookie", pattern: /flask/i }
      ]
    }
  ],
  databases: [
    {
      name: "MySQL",
      weight: 0.7,
      patterns: [
        { type: "html", pattern: /mysql/i },
        { type: "error", pattern: /MySQL/i }
      ]
    },
    {
      name: "PostgreSQL",
      weight: 0.7,
      patterns: [
        { type: "html", pattern: /postgresql/i },
        { type: "error", pattern: /PostgreSQL/i }
      ]
    },
    {
      name: "MongoDB",
      weight: 0.7,
      patterns: [
        { type: "html", pattern: /mongodb/i },
        { type: "jsGlobal", pattern: "MongoDB" }
      ]
    },
    {
      name: "Redis",
      weight: 0.7,
      patterns: [
        { type: "html", pattern: /redis/i },
        { type: "header", pattern: "x-redis-info" },
        { type: "networkRequest", pattern: /redis/i },
        { type: "error", pattern: /Redis/i },
        { type: "jsGlobal", pattern: "Redis" }
      ]      
    }
  ],
  marketing_automation: [
    {
      name: "Mailchimp",
      weight: 0.8,
      patterns: [
        { type: "script", pattern: /cdn-images\.mailchimp\.com/i },
        { type: "html", pattern: /mailchimp/i },
        { type: "networkRequest", pattern: /mailchimp/i },
        { type: "jsGlobal", pattern: /mailchimp/i }
      ]
    },
    {
      name: "Adyen",
      weight: 0.8,
      patterns: [
        { type: "script", pattern: /checkout\.adyen\.com/i },
        { type: "html", pattern: /adyen\.com/i },
        { type: "jsGlobal", pattern: /Adyen/i },
        { type: "networkRequest", pattern: /adyen\.com/i }
      ]
    },
    {
      name: "ActiveCampaign",
      weight: 0.8,
      patterns: [
        { type: "script", pattern: /activehosted\.com/i },
        { type: "networkRequest", pattern: /activehosted\.com/i }
      ]
    }
  ]
};

/**
 * Extracts version numbers from potential global JavaScript variables.
 * @param {string} html - The HTML content of the website.
 * @param {string[]} jsGlobals - Array of potential global JavaScript variable names.
 * @returns {object} - Object containing detected JavaScript versions by variable name (e.g., { 'React.version': '18.0.0', '$.fn.jquery': '3.6.0' }).
 */
const extractJsVersions = (html: string, jsGlobals: string[]): Record<string, string | null> => {
  const jsVersions: Record<string, string | null> = {};

  // Check for angular.version
  const angularVersionMatch = html.match(/angular\.version\s*=\s*\{\s*full:\s*['"]([^'"]+)['"]/i);
  if (angularVersionMatch && angularVersionMatch[1]) {
      jsVersions["angular.version"] = angularVersionMatch[1];
  } else {
      jsVersions["angular.version"] = null;
  }

  // Check for Vue.version
  const vueVersionMatch = html.match(/Vue\.version\s*=\s*['"]([^'"]+)['"]/i);
  if (vueVersionMatch && vueVersionMatch[1]) {
      jsVersions["Vue.version"] = vueVersionMatch[1];
  } else {
      jsVersions["Vue.version"] = null;
  }

  // Check for React.version
  const reactVersionMatch = html.match(/React\.version\s*=\s*['"]([^'"]+)['"]/i);
  if (reactVersionMatch && reactVersionMatch[1]) {
    jsVersions["React.version"] = reactVersionMatch[1];
  } else {
      jsVersions["React.version"] = null; // Indicate that React might be present but version wasn't found this way
  }

  // Check for $.fn.jquery (jQuery version)
  const jqueryVersionMatch = html.match(/\$\.fn\.jquery\s*=\s*['"]([^'"]+)['"]/i);
  if (jqueryVersionMatch && jqueryVersionMatch[1]) {
 jsVersions["$.fn.jquery"] = jqueryVersionMatch[1];
  }else {
      jsVersions["$.fn.jquery"] = null; // Indicate that jQuery was found but version wasn't
 }
 return jsVersions;
}

/**
 * Adds a new signature to the signatures database.
 */
function addSignature(signature: any) {
  if (!signatures[signature.category]) {
    signatures[signature.category] = [];
  }
  signatures[signature.category].push(signature);
}

/**
 * Deletes a signature from the signatures database by name.
 * @param {string} name - The name of the signature to delete.
 */
function deleteSignatureByName(name: string) {
    for (const category in signatures) {
        signatures[category] = signatures[category].filter(sig => sig.name !== name);
    }
}



/**
 * @param {string} url - The URL of the website to detect technologies from.
 * Detect technologies used on a website
 * @param {string} html - The HTML content of the website
 * @param {object} httpHeaders - The HTTP headers from the response
 * @returns {object} - Object containing detected technologies by category
 */
const detectTechnologies = (html: string, httpHeaders: Record<string, string | string[]> = {}): Record<string, Array<{name: string, version: string | null, confidence: number}>> => {
  const detected: Record<string, Array<{name: string, version: string | null, confidence: number}>> = {};
  
  const metaHeaders = extractHeaders(html);
  const headers = { ...metaHeaders, ...httpHeaders };
  
  const metaTags = extractMetaTags(html);
  const cookies = extractCookies(html); // From document.cookie patterns
  
  // Add cookies from HTTP headers (Set-Cookie)
  const headerCookies: Array<{name: string, value: string}> = [];
  if (httpHeaders && httpHeaders['set-cookie']) {
    const setCookieHeader = httpHeaders['set-cookie'];
    const setCookieArray = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    for (const cookieStr of setCookieArray) {
        const nameMatch = cookieStr.match(/^([^=;]+)=/);
        if (nameMatch && nameMatch[1]) {
            // Simplified, real parsing is more complex (attributes, etc.)
            headerCookies.push({ name: nameMatch[1], value: cookieStr.substring(nameMatch[1].length + 1).split(';')[0] });
        }
    }
  }
  const allCookies = [...cookies, ...headerCookies];


  const scripts = extractScripts(html);
  const cssLinks = extractCssLinks(html);
  const potentialJsGlobals = extractPotentialJsGlobals(html);
  const potentialNetworkRequests = extractPotentialNetworkRequests(html);
  const htmlComments = extractHtmlComments(html);
  const jsVersions = extractJsVersions(html, potentialJsGlobals);

  for (const category in signatures) {
    detected[category] = []; 
    const categorySignatures = signatures[category];
    
    for (const signature of categorySignatures) {
      let detectedVersion: string | null = null;
      let maxConfidence = 0;
      let isDetected = false; 
      
      if (signature.versions) {
        for (const versionKey in signature.versions) {
          if (versionKey === 'patterns' || versionKey === 'versionProperty') continue; // Skip special keys
          const versionData = signature.versions[versionKey];
          const versionPatterns = versionData.patterns;
          let versionConfidence = versionData.weight || 0.5; // Default weight if not specified
          let versionMatches = 0;

          if (versionPatterns && versionPatterns.length > 0) {
            for (const pattern of versionPatterns) {
              let matchResult = checkPattern(pattern, html, scripts, cssLinks, headers, metaTags, allCookies, potentialJsGlobals, potentialNetworkRequests, htmlComments, jsVersions);
              
              if (matchResult.match) {
                versionMatches++;
                versionConfidence *= (pattern.weight !== undefined ? pattern.weight : 1); // Apply pattern weight
                if (matchResult.version && !detectedVersion) { // Prioritize version from specific pattern if available
                    detectedVersion = matchResult.version;
                }
              }
            }
          }
          
          if (versionMatches > 0 && versionConfidence > maxConfidence) {
            maxConfidence = versionConfidence;
            if(!detectedVersion) detectedVersion = versionKey; // Use the version key as version if no specific pattern version found
            isDetected = true;
          }
        }
        // Check general patterns if no version-specific one matched strongly or if there are base patterns
        if (signature.versions.patterns) {
            let baseConfidence = signature.weight || 0.5;
            let baseMatches = 0;
            for (const pattern of signature.versions.patterns) {
                let matchResult = checkPattern(pattern, html, scripts, cssLinks, headers, metaTags, allCookies, potentialJsGlobals, potentialNetworkRequests, htmlComments, jsVersions);
                if (matchResult.match) {
                    baseMatches++;
                    baseConfidence *= (pattern.weight !== undefined ? pattern.weight : 1);
                    if (matchResult.version && !detectedVersion) {
                        detectedVersion = matchResult.version;
                    }
                }
            }
            if (baseMatches > 0 && baseConfidence > maxConfidence) {
                maxConfidence = baseConfidence;
                 if (!detectedVersion && signature.versions.versionProperty && jsVersions[signature.versions.versionProperty]) {
                    detectedVersion = jsVersions[signature.versions.versionProperty];
                } else if (!detectedVersion) {
                    detectedVersion = "Unknown"; // Fallback if still no version
                }
                isDetected = true;
            }
        }


        if (isDetected) {
          detected[category].push({ 
            name: signature.name,
            version: detectedVersion, 
            confidence: Math.min(1, maxConfidence) // Ensure confidence does not exceed 1
          });          
        }
      }
      else if (signature.patterns) { // Handle technologies without explicit versions block but with patterns
        let confidence = signature.weight || 0.5;
        let matches = 0;
        let patternVersion: string | null = null;
        
        for (const pattern of signature.patterns) {
          let matchResult = checkPattern(pattern, html, scripts, cssLinks, headers, metaTags, allCookies, potentialJsGlobals, potentialNetworkRequests, htmlComments, jsVersions); 
          
          if (matchResult.match) {
            matches++;
            confidence *= (pattern.weight !== undefined ? pattern.weight : 1);
            if (matchResult.version && !patternVersion) {
                patternVersion = matchResult.version;
            }
            if (confidence > 0.95) break; // Optimization: if high confidence, likely correct
          }
        }
        
        if (matches > 0) {
          // Attempt to get version from jsVersion if not found by patterns
          if (!patternVersion && signature.versionProperty && jsVersions[signature.versionProperty]) {
            patternVersion = jsVersions[signature.versionProperty];
          }

          detected[category].push({ 
            name: signature.name,
            version: patternVersion, 
            confidence: Math.min(1, confidence)
          });
        }
      }
    }
  }
  
  return detected;
}

const checkVersionPattern = (patternRegex: RegExp, jsVersions: Record<string, string | null>, versionProperty: string): { version: string | null, match: boolean } => {
  if (jsVersions && versionProperty && jsVersions[versionProperty] !== undefined && jsVersions[versionProperty] !== null) {
    const versionStr = jsVersions[versionProperty];
    if (versionStr === null) return { version: null, match: false }; // Explicitly check for null
    const match = patternRegex.test(versionStr);
    return { version: match ? versionStr : null, match };
  }
 return { version: null, match: false };
}

const checkPattern = (
    patternObj: any, // Changed name from pattern to patternObj to avoid conflict
    html: string, 
    scripts: string[], 
    cssLinks: string[], 
    headers: Record<string, string | string[]>, 
    metaTags: Record<string, string>, 
    cookies: Array<{name: string, value: string}>, 
    jsGlobals: string[], 
    networkRequests: string[], 
    htmlComments: string[], 
    jsVersions: Record<string, string | null>
): { match: boolean, version?: string | null, matchedValue?: string } => {
  
  let match = false;
  let version: string | null = null;
  let matchedValue: string | undefined;

  const { type, pattern, value: patternValue, name: metaName, content: metaContentRegex, versionProperty, versionCaptureGroup } = patternObj;

  const testAndExtractVersion = (textToTest: string, regexPattern: RegExp) => {
    const execResult = regexPattern.exec(textToTest);
    if (execResult) {
        match = true;
        matchedValue = execResult[0];
        if (versionCaptureGroup && execResult[versionCaptureGroup]) {
            version = execResult[versionCaptureGroup];
        }
    }
  };


  switch (type) {
    case "html":
      testAndExtractVersion(html, pattern);
      break;
    case "script":
      for (const script of scripts) {
        testAndExtractVersion(script, pattern);
        if (match) break;
      }
      break;
    case "css":
       for (const cssLink of cssLinks) {
        testAndExtractVersion(cssLink, pattern);
        if (match) break;
      }
      // Additionally, check inline styles if a more complex pattern indicates it
      // For simplicity, this example only checks linked CSS files.
      // To check inline CSS:
      // const styleRegex = /<style[^>]*>([\s\S]*?)<\/style>/gi;
      // let styleMatch;
      // while ((styleMatch = styleRegex.exec(html)) !== null) {
      //   testAndExtractVersion(styleMatch[1], pattern);
      //   if (match) break;
      // }
      break;
    case "header":
      const headerKey = pattern.toLowerCase(); // Header names are case-insensitive
      const headerVal = headers[headerKey];
      if (headerVal !== undefined) {
        const headerValStr = Array.isArray(headerVal) ? headerVal.join(', ') : headerVal;
        if (patternValue) { // If a specific value regex is provided for the header
            testAndExtractVersion(headerValStr, patternValue);
        } else { // Just check for header existence
            match = true;
            matchedValue = headerKey;
        }
      }
      break;
    case "meta":
      const metaTagKey = (metaName || pattern.name || pattern).toLowerCase(); // metaName from patternObj.name or patternObj.pattern.name
      const metaTagValue = metaTags[metaTagKey];
      if (metaTagValue !== undefined) {
        if (metaContentRegex) { // If content regex is provided
            testAndExtractVersion(metaTagValue, metaContentRegex);
        } else { // Check for meta tag existence by name
            match = true;
            matchedValue = metaTagKey;
        }
      }
      break;
    case "cookie":
      for (const cookie of cookies) {
        // Test pattern against cookie name
        if (pattern.test(cookie.name)) {
            match = true;
            matchedValue = cookie.name;
            // If pattern also needs to match cookie value (not typical in simple Wappalyzer-like sigs)
            // if (patternValue && patternValue.test(cookie.value)) { match = true; } else if (!patternValue) { match = true; }
            break;
        }
        // Optionally, test pattern against cookie value if specified (e.g. pattern for value, name for cookie name)
        // if (patternObj.name && cookie.name === patternObj.name && pattern.test(cookie.value)) {
        //     match = true;
        //     matchedValue = cookie.value;
        //     break;
        // }
      }
      break;
    case "jsGlobal":
      // Check if the global variable name (pattern) appears in the list of extracted globals or in HTML
      if (jsGlobals.includes(pattern) || new RegExp(`\\b${pattern}\\b`, 'i').test(html)) {
        match = true;
        matchedValue = pattern;
      }
      break;
    case "networkRequest":
        for (const req of networkRequests) {
            testAndExtractVersion(req, pattern);
            if (match) break;
        }
        if (!match) { // Fallback to check HTML content if not found in explicit requests
            testAndExtractVersion(html, pattern);
        }
      break;
    case "jsVersion":
      if (versionProperty && jsVersions[versionProperty]) {
        const detectedVer = jsVersions[versionProperty];
        if (detectedVer !== null) { // Ensure version is not null
            if (pattern instanceof RegExp) { // The 'pattern' here is the version format regex
                const versionMatchResult = pattern.exec(detectedVer);
                if (versionMatchResult) {
                    match = true;
                    version = versionMatchResult[versionCaptureGroup || 0]; // Use capture group or whole match
                    matchedValue = detectedVer;
                }
            } else if (typeof pattern === 'string') { // Simple string comparison for version
                if (detectedVer.includes(pattern)) {
                    match = true;
                    version = detectedVer; // Or a more specific extraction if needed
                    matchedValue = detectedVer;
                }
            }
        }
      }
      break;
    case "htmlComment":
       for (const comment of htmlComments) {
        testAndExtractVersion(comment, pattern);
        if (match) break;
      }
      break;
    case "error": // Basic error pattern check in HTML
        testAndExtractVersion(html, pattern);
        break;
    default:
      match = false;
  }
  return { match, version, matchedValue };
}

const extractCookies = (html: string): Array<{name: string, value: string}> => {
 const cookiesArr: Array<{name: string, value: string}> = [];
 const cookieRegex = /document\.cookie\s*=\s*['"]([^'"]+?)=([^;'"]*)/gi;
 let match;
 while (match = cookieRegex.exec(html)) {
 const name = match[1];
 const value = match[2];
 cookiesArr.push({ name: name, value: value });
  }
  return cookiesArr;
}

const extractScripts = (html: string): string[] => {
  const scriptsArr: string[] = [];
  const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while (match = scriptRegex.exec(html)) {
    scriptsArr.push(match[1]);
  }
  // Also consider inline script content for certain patterns if needed, though Wappalyzer focuses on src
  return scriptsArr;
}

const extractCssLinks = (html: string): string[] => {
  const cssLinksArr: string[] = [];
  const cssRegex = /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/gi;
  const altCssRegex = /<link[^>]*href=["']([^"']+\.css[^"']*)["'][^>]*rel=["']stylesheet["'][^>]*>/gi; // Added rel=stylesheet to be more specific
  const altCssRegex2 = /<link[^>]*href=["']([^"']+\.css[^"']*)["'][^>]*>/gi; // More generic CSS link
  let match;
  
  while (match = cssRegex.exec(html)) {
    cssLinksArr.push(match[1]);
  }
  while (match = altCssRegex.exec(html)) {
    if (!cssLinksArr.includes(match[1])) cssLinksArr.push(match[1]);
  }
   while (match = altCssRegex2.exec(html)) {
    if (!cssLinksArr.includes(match[1])) cssLinksArr.push(match[1]);
  }
  
  return cssLinksArr;
}

const extractMetaTags = (html: string): Record<string, string> => {
  const metaTagsObj: Record<string, string> = {};
  // Regex for &lt;meta name="..." content="..."&gt;
  const metaNameRegex = /<meta[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']*)["'][^>]*>/gi;
  // Regex for &lt;meta property="..." content="..."&gt; (e.g., Open Graph)
  const metaPropertyRegex = /<meta[^>]*property=["']([^"']+)["'][^>]*content=["']([^"']*)["'][^>]*>/gi;
  // Regex for &lt;meta content="..." name="..."&gt; (alternative order)
  const altMetaNameRegex = /<meta[^>]*content=["']([^"']*)["'][^>]*name=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while (match = metaNameRegex.exec(html)) {
    metaTagsObj[match[1].toLowerCase()] = match[2];
  }
  while (match = metaPropertyRegex.exec(html)) {
    metaTagsObj[match[1].toLowerCase()] = match[2];
  }
  while (match = altMetaNameRegex.exec(html)) {
    metaTagsObj[match[2].toLowerCase()] = match[1];
  }
  
  return metaTagsObj;
}

const extractHeaders = (html: string): Record<string, string> => {
  const headersObj: Record<string, string> = {};
  // Primarily, headers are from HTTP response, not extractable from HTML directly in this manner.
  // This function might be for meta http-equiv tags, which simulate headers.
  const headerRegex = /<meta[^>]*http-equiv=["']([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>/gi;
  const altHeaderRegex = /<meta[^>]*content=["']([^"']+)["'][^>]*http-equiv=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while (match = headerRegex.exec(html)) {
    headersObj[match[1].toLowerCase()] = match[2];
  }
  
  while (match = altHeaderRegex.exec(html)) {
    headersObj[match[2].toLowerCase()] = match[1];
  }
  
  return headersObj;
}

const extractHtmlComments = (html: string): string[] => {
    const comments: string[] = [];
    const commentRegex = /&lt;!--([\s\S]*?)--&gt;/gi;
    let match;

    while ((match = commentRegex.exec(html)) !== null) {
        comments.push(match[1].trim()); // Trim whitespace from comment content
    }
    return comments;
}

const extractPotentialJsGlobals = (html: string): string[] => {
  const globals: Set<string> = new Set(); // Use Set to avoid duplicates
  // Regex for var, let, const, window. assignments
  const globalRegex = /(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=|window\.([a-zA-Z_$][\w$]*)\s*=/gi;
  const inlineScriptRegex = /<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi; // Only inline scripts
  let match;
  let scriptMatch;
  
  while (scriptMatch = inlineScriptRegex.exec(html)) {
    const scriptContent = scriptMatch[1];
    while (match = globalRegex.exec(scriptContent)) {
      if (match[1]) globals.add(match[1]); // From var/let/const
      if (match[2]) globals.add(match[2]); // From window.
    }
  }
  
  // Add common globals that might be referenced without explicit declaration in analyzed snippet
  const commonGlobals = ["React", "ReactDOM", "Vue", "jQuery", "$", "_", "angular", "Stripe", "paypal", "ga", "gtag", "dataLayer", "mixpanel", "analytics", "Optanon", "OneTrust", "bitpay", "wp", "Drupal", "MongoDB", "Redis"];
  commonGlobals.forEach(global => {
    // Check if global exists as a whole word to avoid partial matches in HTML context
    // This is a heuristic; true global detection requires JS execution.
    if (new RegExp(`\\b${global}\\b`).test(html)) { 
      globals.add(global);
    }
  });
  return Array.from(globals);
}

const extractPotentialNetworkRequests = (html: string): string[] => {
  const requests: Set<string> = new Set(); // Use Set to avoid duplicates
  // Regex to find full URLs (http/https) within strings (e.g. in script tags or data attributes)
  const urlRegex = /(['"])(https?:\/\/[^"'\s]+)\1/gi; 
  let match;
  
  while (match = urlRegex.exec(html)) {
    try {
      const url = new URL(match[2]);
      // Add hostname and potentially significant parts of the path
      let path = url.pathname;
      // Simplify common tracking paths or generic paths
      if (path === '/' || path.startsWith('/v1') || path.startsWith('/v2') || path.startsWith('/api')) {
        // keep it simple
      } else if (path.length > 50) {
        path = path.substring(0, 50) + '...'; // Truncate long paths
      }
      requests.add(url.hostname + path);
    } catch (e) {
      // If URL parsing fails, try a simpler extraction for the domain-like part
      const domainMatch = match[2].match(/https?:\/\/([^/?#]+)/);
      if (domainMatch && domainMatch[1]) {
        requests.add(domainMatch[1]);
      }
    }
  }
  
  return Array.from(requests);
}

// Adding the new Google Analytics signature using the addSignature function
addSignature({
    name: "Google Analytics",
    category: "analytics", // Ensure this category exists, or addSignature creates it
    // weight: 0.8, // Not directly used by addSignature as per provided code
    patterns: [
        { type: "cookie", pattern: /^_ga/, weight: 0.8 }
    ]
});

export {
  signatures, // Export the main signatures database
  extractJsVersions,
  detectTechnologies,
  addSignature,
  deleteSignatureByName,
  extractCookies,
  checkVersionPattern,
  checkPattern,
  extractScripts,
  extractCssLinks,
  extractMetaTags,
  extractHeaders,
  extractHtmlComments,
  extractPotentialJsGlobals,
  extractPotentialNetworkRequests
};