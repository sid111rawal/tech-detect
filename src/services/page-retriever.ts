'use server';

import type { Browser, Page } from 'puppeteer-core';
import puppeteer from 'puppeteer-core';
import chromium from '@sparticuz/chromium-min';

export interface PageContentResult {
  html: string | null;
  headers?: Record<string, string | string[]>; // Response headers
  setCookieStrings?: string[]; // Array of raw Set-Cookie header strings
  status?: number; // HTTP status code
  finalUrl?: string; // URL after redirects
  error?: string;
  retrievedFromCache?: boolean;
}

// Simple in-memory cache with TTL
const cache = new Map<string, { data: PageContentResult; timestamp: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function generateCacheKey(url: string): string {
  // Added "v2" to cache key to avoid conflicts if old cache entries exist
  // Consider a more robust cache invalidation strategy if needed.
  return `pageContent:v2:${url}`;
}


async function launchBrowser(): Promise<Browser | null> {
  try {
    const executablePath = process.env.NODE_ENV === 'production'
      ? await chromium.executablePath()
      : puppeteer.executablePath(); // Fallback for local dev if chromium env var isn't set

    if (!executablePath && process.env.NODE_ENV === 'production') {
        console.error('[Service/PageRetriever] Chromium executable not found for production.');
        return null;
    }
    
    console.log(`[Service/PageRetriever] Launching browser with executable: ${executablePath || 'default puppeteer path'}`);

    const browser = await puppeteer.launch({
      args: process.env.NODE_ENV === 'production' ? chromium.args : [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        // '--single-process', // Not recommended for stability, but can save memory
        '--disable-gpu'
      ],
      defaultViewport: chromium.defaultViewport,
      executablePath: executablePath || undefined, // Use undefined if puppeteer's default is fine for local
      headless: process.env.NODE_ENV === 'production' ? chromium.headless : true, // Ensure headless for prod, true for local
      ignoreHTTPSErrors: true,
    });
    console.log('[Service/PageRetriever] Browser launched successfully.');
    return browser;
  } catch (error) {
    console.error('[Service/PageRetriever] Error launching browser:', error);
    throw new Error(`Failed to launch browser: ${(error as Error).message}`);
  }
}


/**
 * Retrieves the HTML content, headers, and cookies of a given URL using Puppeteer.
 * Uses an in-memory cache to avoid re-fetching recently accessed URLs.
 * @param url The URL to fetch.
 * @returns A promise that resolves to an object containing the page data or an error message.
 */
export async function retrievePageContent(url: string): Promise<PageContentResult> {
  const cacheKey = generateCacheKey(url);
  const cachedEntry = cache.get(cacheKey);

  if (cachedEntry && (Date.now() - cachedEntry.timestamp < CACHE_TTL)) {
    console.log(`[Service/PageRetriever] Cache hit for URL: ${url}`);
    return { ...cachedEntry.data, retrievedFromCache: true };
  }
  console.log(`[Service/PageRetriever] Cache miss or stale for URL: ${url}. Attempting to fetch with Puppeteer...`);

  let browser: Browser | null = null;
  try {
    browser = await launchBrowser();
    if (!browser) {
      throw new Error("Browser could not be launched.");
    }

    const page: Page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 TechDetective/1.0');
    await page.setExtraHTTPHeaders({
      'Accept-Language': 'en-US,en;q=0.9'
    });
    // Disable JavaScript execution if not strictly needed for initial HTML, can speed up and simplify.
    // await page.setJavaScriptEnabled(false);


    console.log(`[Service/PageRetriever] Navigating to URL: ${url}`);
    const response = await page.goto(url, {
      waitUntil: 'networkidle0', // Waits for the network to be idle (no new connections for 500ms). Alternatives: 'load', 'domcontentloaded', 'networkidle2'
      timeout: 30000, // 30 seconds timeout for navigation
    });

    if (!response) {
      throw new Error('Navigation failed, no response received.');
    }
    
    const responseHeaders: Record<string, string | string[]> = {};
    const rawHeaders = response.headers(); // Puppeteer's response.headers() gives an object
    for (const key in rawHeaders) {
        responseHeaders[key.toLowerCase()] = rawHeaders[key];
    }

    const setCookieHeaderValues = response.headers()['set-cookie'] 
        ? (Array.isArray(response.headers()['set-cookie']) 
            ? response.headers()['set-cookie'] as string[]
            : [response.headers()['set-cookie'] as string]) 
        : [];


    const status = response.status();
    let htmlContent: string | null;

    if (!response.ok()) {
      const errorText = `HTTP error ${status} ${response.statusText()}`;
      console.warn(`[Service/PageRetriever] Failed to fetch URL ${url} (Puppeteer): ${errorText}`);
      try {
        htmlContent = await page.content(); // Try to get content even on error for analysis
      } catch (contentError) {
        htmlContent = null;
        console.warn(`[Service/PageRetriever] Could not get page content on error for ${url}:`, contentError);
      }
      const result: PageContentResult = {
        html: htmlContent,
        error: `Failed to fetch (Puppeteer): ${errorText}`,
        status: status,
        headers: responseHeaders,
        setCookieStrings: setCookieHeaderValues,
        finalUrl: page.url(),
        retrievedFromCache: false,
      };
      cache.set(cacheKey, { data: result, timestamp: Date.now() });
      return result;
    }
    
    htmlContent = await page.content();
    console.log(`[Service/PageRetriever] Successfully fetched content for URL (Puppeteer): ${page.url()} (Status: ${status}, Content length: ${htmlContent?.length || 0})`);
    
    const successResult: PageContentResult = {
      html: htmlContent,
      headers: responseHeaders,
      setCookieStrings: setCookieHeaderValues,
      status: status,
      finalUrl: page.url(),
      retrievedFromCache: false,
    };
    cache.set(cacheKey, { data: successResult, timestamp: Date.now() });
    return successResult;

  } catch (error: any) {
    console.error(`[Service/PageRetriever] Error fetching URL ${url} with Puppeteer:`, error);
    let detailedErrorMessage = error.message || 'An unknown error occurred during Puppeteer fetching.';
     if (error.name === 'TimeoutError') {
      detailedErrorMessage = `Navigation timed out for ${url}. The page might be too slow or complex.`;
    }
    
    const errorResult: PageContentResult = {
      html: null,
      error: detailedErrorMessage,
      finalUrl: url, 
      status: undefined, 
      retrievedFromCache: false,
    };
    return errorResult;
  } finally {
    if (browser) {
      console.log('[Service/PageRetriever] Closing browser.');
      await browser.close();
    }
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

  const cacheKey = `robots:${robotsUrl}`;
  const cachedRobots = cache.get(cacheKey);
  if (cachedRobots && (Date.now() - cachedRobots.timestamp < CACHE_TTL)) {
      console.log(`[Service/PageRetriever] Cache hit for robots.txt: ${robotsUrl}`);
      return (cachedRobots.data as { content: string | null }).content;
  }
  console.log('[Service/PageRetriever] Cache miss or stale for robots.txt. Attempting to fetch from:', robotsUrl);


  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 seconds timeout for robots.txt

  try {
    // Using built-in fetch for robots.txt as it's simpler and doesn't need JS execution
    const response = await fetch(robotsUrl, {
      // @ts-ignore This is valid for node-fetch / native fetch with AbortController
      signal: controller.signal, 
      headers: {
        'User-Agent': 'TechDetectiveBot/1.0 (+https://your-tool-website.com/bot-info)', 
      },
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      if (response.status === 404) {
        console.log(`[Service/PageRetriever] robots.txt not found for ${baseUrl} (Status: 404)`);
      } else {
        console.warn(`[Service/PageRetriever] Failed to fetch robots.txt for ${baseUrl}: ${response.status} ${response.statusText}`);
      }
      cache.set(cacheKey, { data: { content: null }, timestamp: Date.now() });
      return null;
    }

    const textContent = await response.text();
    console.log(`[Service/PageRetriever] Successfully fetched robots.txt for ${baseUrl}`);
    cache.set(cacheKey, { data: { content: textContent }, timestamp: Date.now() });
    return textContent;

  } catch (error: any) {
    clearTimeout(timeoutId);
     let detailedErrorMessage = error.message || 'Unknown error fetching robots.txt.';
     if (error.name === 'AbortError' || (error.cause && (error.cause as Error).name === 'TimeoutError')) {
      detailedErrorMessage = `Request for robots.txt timed out for ${baseUrl}.`;
    } else if (error.cause && typeof error.cause === 'object') {
      const cause = error.cause as any; // Node.js fetch error structure
      detailedErrorMessage = `Network error fetching robots.txt: ${cause.code || (cause as Error).message || 'Unknown network issue'}.`;
      console.error(`[Service/PageRetriever] Fetch robots.txt error cause for URL ${robotsUrl}:`, JSON.stringify(error.cause, Object.getOwnPropertyNames(error.cause)));
    } else if (error.cause) { // Generic cause
        detailedErrorMessage = `Network error (robots.txt). Cause: ${String(error.cause)}`;
    }
    console.warn(`[Service/PageRetriever] Error fetching robots.txt for ${baseUrl}: ${detailedErrorMessage}`);
    return null;
  }
}
