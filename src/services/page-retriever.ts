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
    const setCookieHeader = response.headers.get('set-cookie');
    if (setCookieHeader) {
        cookiesFromHeader = setCookieHeader;
    }


    if (!response.ok) {
      console.error(`[Service/PageRetriever] Failed to fetch URL ${url}: ${response.status} ${response.statusText}`);
      // Attempt to read body for error pages if possible, but prioritize error message
      let errorHtml: string | null = null;
      try {
        errorHtml = await response.text();
      } catch (textError) {
        console.warn(`[Service/PageRetriever] Could not read error response body for ${url}:`, textError);
      }
      return {
        html: errorHtml, // May contain error details from the server
        error: `Failed to fetch: ${response.status} ${response.statusText}`,
        status: response.status,
        headers: responseHeaders,
        finalUrl: response.url
      };
    }

    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('text/html')) {
        console.warn(`[Service/PageRetriever] URL ${url} returned non-HTML content-type: ${contentType}. Content will be processed, but HTML-specific signatures might not match.`);
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
      return { html: null, error: 'Request timed out while fetching content after 15 seconds.', finalUrl: url, status: undefined };
    }

    let detailedErrorMessage = error.message || 'Unknown error fetching content.';
    let hostname = url;
    try {
        hostname = new URL(url).hostname;
    } catch (e) { /* ignore if URL is invalid */ }

    if (error.cause && typeof error.cause === 'object') {
      const cause = error.cause as any;
      if (cause.code) {
        if (cause.code === 'ENOTFOUND') {
            detailedErrorMessage = `DNS resolution failed for the host: ${hostname}. Ensure the domain is correct and reachable.`;
        } else if (cause.code === 'ECONNREFUSED') {
            detailedErrorMessage = `Connection refused by the server at ${hostname}. The server might be down or blocking requests.`;
        } else if (cause.code === 'UND_ERR_CONNECT_TIMEOUT' || cause.code === 'ETIMEDOUT') {
            detailedErrorMessage = `Connection timed out trying to reach ${hostname}. The website might be temporarily unavailable or there could be network issues. Please verify the URL and try again later.`;
        } else {
            detailedErrorMessage = `Network error: ${cause.code}. Please check server connectivity and DNS resolution.`;
        }
      } else if (cause.message) {
        detailedErrorMessage = `Network error details: ${cause.message}.`;
      }
      console.error(`[Service/PageRetriever] Fetch error cause for URL ${url}:`, JSON.stringify(error.cause, Object.getOwnPropertyNames(error.cause)));
    } else if (error.cause) {
        detailedErrorMessage = `Network error. Cause: ${String(error.cause)}`;
        console.error(`[Service/PageRetriever] Fetch error cause (non-object) for URL ${url}: ${String(error.cause)}`);
    }
    
    return {
      html: null,
      error: detailedErrorMessage,
      finalUrl: url,
      status: undefined
    };
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
      console.warn(`[Service/PageRetriever] Request for robots.txt timed out for ${baseUrl}.`);
      return null;
    }
    let detailedErrorMessage = error.message || 'Unknown error fetching robots.txt.';
     if (error.cause && typeof error.cause === 'object') {
      const cause = error.cause as any;
      if (cause.code) { 
        detailedErrorMessage = `Network error fetching robots.txt: ${cause.code}.`;
      } else if (cause.message) {
        detailedErrorMessage = `Network error details (robots.txt): ${cause.message}.`;
      }
      console.error(`[Service/PageRetriever] Fetch robots.txt error cause for URL ${robotsUrl}:`, JSON.stringify(error.cause, Object.getOwnPropertyNames(error.cause)));
    } else if (error.cause) {
        detailedErrorMessage = `Network error (robots.txt). Cause: ${String(error.cause)}`;
    }
    console.warn(`[Service/PageRetriever] Non-timeout error fetching robots.txt for ${baseUrl}: ${detailedErrorMessage}`);
    return null;
  }
}
