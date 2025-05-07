
'use server';

export interface PageContentResult {
  html: string | null;
  headers?: Record<string, string | string[]>; // Response headers
  cookies?: string; // Concatenated Set-Cookie header values, or other cookie info
  status?: number; // HTTP status code
  finalUrl?: string; // URL after redirects
  error?: string;
}

/**
 * Retrieves the HTML content, headers, and cookies of a given URL.
 * @param url The URL to fetch.
 * @returns A promise that resolves to an object containing the page data or an error message.
 */
export async function retrievePageContent(url: string): Promise<PageContentResult> {
  console.log('[Service/PageRetriever] Attempting to fetch content for URL:', url);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 seconds timeout

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      redirect: 'follow',
    });
    clearTimeout(timeoutId);

    const responseHeaders: Record<string, string | string[]> = {};
    response.headers.forEach((value, key) => {
      const existing = responseHeaders[key];
      if (existing) {
        if (Array.isArray(existing)) {
          existing.push(value);
        } else {
          responseHeaders[key] = [existing, value];
        }
      } else {
        responseHeaders[key] = value;
      }
    });

    let cookiesFromHeader: string | undefined;
    const setCookieHeader = response.headers.get('set-cookie'); // This might only get the first if multiple
    // For multiple Set-Cookie headers, a more robust approach might be needed depending on environment
    // For Node.js `fetch`, `response.headers.raw()['set-cookie']` would give an array.
    // Browsers typically combine them. For now, assume `get` gives a usable string.
    if (setCookieHeader) {
        cookiesFromHeader = setCookieHeader;
    }


    if (!response.ok) {
      console.error(`[Service/PageRetriever] Failed to fetch URL ${url}: ${response.status} ${response.statusText}`);
      return {
        html: null,
        error: `Failed to fetch: ${response.status} ${response.statusText}`,
        status: response.status,
        headers: responseHeaders,
        finalUrl: response.url
      };
    }

    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('text/html')) {
        console.warn(`[Service/PageRetriever] URL ${url} returned non-HTML content-type: ${contentType}`);
        // Allow processing non-HTML for header/cookie based detection, but HTML dependent patterns will fail.
    }

    const textContent = await response.text();
    console.log(`[Service/PageRetriever] Successfully fetched content for URL: ${url} (Status: ${response.status}, Content length: ${textContent.length}, Final URL: ${response.url})`);
    return {
      html: textContent,
      headers: responseHeaders,
      cookies: cookiesFromHeader,
      status: response.status,
      finalUrl: response.url
    };
  } catch (error: any) {
    clearTimeout(timeoutId);
    console.error(`[Service/PageRetriever] Error fetching URL ${url}:`, error);
    if (error.name === 'AbortError' || (error.cause && error.cause.name === 'TimeoutError')) {
      return { html: null, error: 'Request timed out while fetching content.' };
    }
    return { html: null, error: error.message || 'Unknown error fetching content' };
  }
}


/**
 * Retrieves the robots.txt file for a given base URL.
 * @param baseUrl The base URL of the website (e.g., https://example.com).
 * @returns A promise that resolves to the robots.txt content as a string, or null if an error occurs or not found.
 */
export async function retrieveRobotsTxt(baseUrl: string): Promise<string | null> {
  let robotsUrl = '';
  try {
    const urlObj = new URL(baseUrl);
    robotsUrl = `${urlObj.protocol}//${urlObj.hostname}/robots.txt`;
  } catch (e) {
    console.error(`[Service/PageRetriever] Invalid base URL for robots.txt: ${baseUrl}`, e);
    return null;
  }

  console.log('[Service/PageRetriever] Attempting to fetch robots.txt from:', robotsUrl);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 seconds timeout for robots.txt

  try {
    const response = await fetch(robotsUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'TechDetectiveBot/1.0 (+https://your-tool-website.com/bot-info)', // Be a good bot citizen
      },
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      if (response.status === 404) {
        console.log(`[Service/PageRetriever] robots.txt not found for ${baseUrl} (Status: 404)`);
      } else {
        console.warn(`[Service/PageRetriever] Failed to fetch robots.txt for ${baseUrl}: ${response.status} ${response.statusText}`);
      }
      return null;
    }

    const textContent = await response.text();
    console.log(`[Service/PageRetriever] Successfully fetched robots.txt for ${baseUrl}`);
    return textContent;
  } catch (error: any) {
    clearTimeout(timeoutId);
    console.error(`[Service/PageRetriever] Error fetching robots.txt for ${baseUrl}:`, error);
     if (error.name === 'AbortError' || (error.cause && error.cause.name === 'TimeoutError')) {
      return null; // Timeout is not a critical error for robots.txt
    }
    return null;
  }
}
