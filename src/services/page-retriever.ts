
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
        // 'Cookie': 'your_test_cookies_here_if_needed' // Not typically sent for initial generic request
      },
      redirect: 'follow', 
    });
    clearTimeout(timeoutId);

    const responseHeaders: Record<string, string | string[]> = {};
    response.headers.forEach((value, key) => {
      // Handle multi-value headers like Set-Cookie correctly
      if (responseHeaders[key]) {
        if (Array.isArray(responseHeaders[key])) {
          (responseHeaders[key] as string[]).push(value);
        } else {
          responseHeaders[key] = [responseHeaders[key] as string, value];
        }
      } else {
        responseHeaders[key] = value;
      }
    });
    
    let cookiesFromHeader: string | undefined;
    const setCookieHeader = response.headers.get('set-cookie');
    if (setCookieHeader) {
        // This simplistic approach might combine multiple Set-Cookie headers if not handled as an array by fetch's Headers object.
        // A more robust solution might involve parsing `response.headers.raw()['set-cookie']` if available and supported.
        // For now, we'll just take what `get` provides, which might be a comma-separated string for multiple cookies.
        cookiesFromHeader = setCookieHeader;
    }
    // Note: We can't access document.cookie on the server. This `cookiesFromHeader` is from `Set-Cookie`.


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
    if (error.name === 'AbortError') {
      return { html: null, error: 'Request timed out while fetching content.' };
    }
    return { html: null, error: error.message || 'Unknown error fetching content' };
  }
}