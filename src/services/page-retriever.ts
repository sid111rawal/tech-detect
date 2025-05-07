
'use server';

export interface PageContent {
  html: string | null;
  error?: string;
}

/**
 * Retrieves the HTML content of a given URL.
 * @param url The URL to fetch.
 * @returns A promise that resolves to an object containing the HTML or an error message.
 */
export async function retrievePageContent(url: string): Promise<PageContent> {
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
      redirect: 'follow', // handle redirects
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`Failed to fetch URL ${url}: ${response.status} ${response.statusText}`);
      return { html: null, error: `Failed to fetch: ${response.status} ${response.statusText}` };
    }

    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('text/html')) {
        console.warn(`URL ${url} returned non-HTML content-type: ${contentType}`);
        // Depending on strictness, you might want to return an error or try to parse anyway
        // For now, we'll proceed but this is a potential point of failure for non-HTML pages
    }

    const textContent = await response.text();
    return { html: textContent };
  } catch (error: any) {
    clearTimeout(timeoutId);
    console.error(`Error fetching URL ${url}:`, error);
    if (error.name === 'AbortError') {
      return { html: null, error: 'Request timed out while fetching content.' };
    }
    return { html: null, error: error.message || 'Unknown error fetching content' };
  }
}
