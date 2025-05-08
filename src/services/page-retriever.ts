'use server';

import type { Browser, Page } from 'puppeteer-core';
import puppeteer from 'puppeteer-core';
import chromium from '@sparticuz/chromium-min';
import { fetch as undiciFetch, Headers as UndiciHeaders, type Response as UndiciResponse } from 'undici';

export interface PageContentResult {
  html: string | null;
  headers?: Record<string, string | string[]>; // Response headers
  setCookieStrings?: string[]; // Array of raw Set-Cookie header strings
  status?: number; // HTTP status code
  finalUrl?: string; // URL after redirects
  error?: string;
  retrievedFromCache?: boolean;
  fetchMethod?: 'puppeteer' | 'fetch'; // Indicate which method was used
}

// Simple in-memory cache with TTL
const cache = new Map<string, { data: PageContentResult | { content: string | null }; timestamp: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function generateCacheKey(type: 'pageContent' | 'robots', identifier: string): string {
  return `${type}:v4:${identifier}`; // Incremented version
}


async function launchBrowser(): Promise<Browser> {
  try {
    let resolvedExecutablePath: string | undefined;

    try {
      console.log('[Service/PageRetriever] Attempting to get executablePath from @sparticuz/chromium-min...');
      resolvedExecutablePath = await chromium.executablePath();
      if (resolvedExecutablePath) {
        console.log('[Service/PageRetriever] Using executablePath from @sparticuz/chromium-min:', resolvedExecutablePath);
      } else {
        console.warn('[Service/PageRetriever] @sparticuz/chromium-min did not provide an executablePath.');
      }
    } catch (e) {
      console.warn('[Service/PageRetriever] Error getting executablePath from @sparticuz/chromium-min:', e);
    }

    if (!resolvedExecutablePath && process.env.NODE_ENV !== 'production') {
      console.log('[Service/PageRetriever] Attempting fallback to puppeteer.executablePath() for local development...');
      try {
        const puppeteerDefaultPath = puppeteer.executablePath(); 
        if (puppeteerDefaultPath) {
          resolvedExecutablePath = puppeteerDefaultPath;
          console.log('[Service/PageRetriever] Using executablePath from puppeteer default (likely local full puppeteer):', resolvedExecutablePath);
        } else {
          console.warn('[Service/PageRetriever] puppeteer.executablePath() did not provide a path (expected for puppeteer-core if no local full puppeteer).');
        }
      } catch (e) {
         console.warn('[Service/PageRetriever] Error calling puppeteer.executablePath():', e);
      }
    }

    if (!resolvedExecutablePath || typeof resolvedExecutablePath !== 'string') {
      const noPathMessage = "Chromium executable path could not be resolved. " +
                            "Ensure @sparticuz/chromium-min is correctly installed and can access/download Chromium, " +
                            "or a local Chromium installation is available and discoverable by Puppeteer for local development. " +
                            "Current resolvedExecutablePath: " + resolvedExecutablePath;
      console.error(`[Service/PageRetriever] ${noPathMessage}`);
      throw new Error(noPathMessage);
    }

    console.log(`[Service/PageRetriever] Final executablePath to be used: ${resolvedExecutablePath}`);
    console.log(`[Service/PageRetriever] Using headless mode: ${chromium.headless}`);


    const browser = await puppeteer.launch({
      args: chromium.args,
      defaultViewport: chromium.defaultViewport,
      executablePath: resolvedExecutablePath, 
      headless: chromium.headless,
      ignoreHTTPSErrors: true,
    });
    console.log('[Service/PageRetriever] Browser launched successfully.');
    return browser;

  } catch (error) {
    console.error('[Service/PageRetriever] Error in launchBrowser:', error);
    let errorMessage = (error instanceof Error) ? error.message : String(error);
    if (errorMessage.toLowerCase().includes("path argument must be of type string")) {
        errorMessage = "Chromium executable path was invalid or undefined. Ensure it's a valid string. Original error: " + errorMessage;
    }
    // This specific error message is for the user's reported issue.
    if (errorMessage.includes("Chromium executable path could not be resolved")) {
        throw new Error(`Failed to launch browser: ${errorMessage}`);
    }
    throw new Error(`Failed to launch browser: ${errorMessage}`);
  }
}


async function fetchWithUndici(url: string): Promise<PageContentResult> {
  console.log(`[Service/PageRetriever] Attempting to fetch URL with undici: ${url}`);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout

  try {
    const response: UndiciResponse = await undiciFetch(url, {
      // @ts-ignore undici fetch type for signal might expect AbortSignal from 'node:AbortController'
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 TechDetective/1.0',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      },
      redirect: 'follow', // Handle redirects
    });
    clearTimeout(timeoutId);

    const htmlContent = await response.text();
    const status = response.status;
    const finalUrl = response.url;

    const responseHeaders: Record<string, string | string[]> = {};
    response.headers.forEach((value, key) => {
      // For headers that can appear multiple times (like Set-Cookie), store as array
      const existing = responseHeaders[key.toLowerCase()];
      if (existing) {
        if (Array.isArray(existing)) {
          existing.push(value);
        } else {
          responseHeaders[key.toLowerCase()] = [existing, value];
        }
      } else {
        responseHeaders[key.toLowerCase()] = value;
      }
    });
    
    const setCookieStrings = response.headers.getSetCookie ? response.headers.getSetCookie() : [];

    if (!response.ok) {
      const errorText = `HTTP error ${status} ${response.statusText || ''}`;
      console.warn(`[Service/PageRetriever] Failed to fetch URL ${url} (undici): ${errorText}`);
      return {
        html: htmlContent, // HTML might still be available on error pages
        error: `Failed to fetch (undici): ${errorText}`,
        status,
        headers: responseHeaders,
        setCookieStrings,
        finalUrl,
        fetchMethod: 'fetch',
      };
    }
    
    console.log(`[Service/PageRetriever] Successfully fetched content for URL (undici): ${finalUrl} (Status: ${status})`);
    return {
      html: htmlContent,
      headers: responseHeaders,
      setCookieStrings,
      status,
      finalUrl,
      fetchMethod: 'fetch',
    };
  } catch (error: any) {
    clearTimeout(timeoutId);
    let detailedErrorMessage = error.message || 'An unknown error occurred during undici fetch.';
    if (error.name === 'AbortError' || error.name === 'TimeoutError' || (error.cause && (error.cause as Error).name === 'TimeoutError')) {
      detailedErrorMessage = `Request timed out for ${url} (undici).`;
    } else if (error.cause && typeof error.cause === 'object' && (error.cause as any).code) {
        detailedErrorMessage = `Network error (undici): ${(error.cause as any).code}. Please check server connectivity and DNS resolution.`;
    } else if (error.code) {
        detailedErrorMessage = `Network error (undici): ${error.code}. Please check server connectivity and DNS resolution.`;
    }
    
    console.error(`[Service/PageRetriever] Error fetching URL ${url} with undici:`, detailedErrorMessage);
    return {
      html: null,
      error: detailedErrorMessage,
      finalUrl: url,
      status: undefined,
      fetchMethod: 'fetch',
    };
  }
}


/**
 * Retrieves the HTML content, headers, and cookies of a given URL.
 * Tries Puppeteer first, then falls back to basic fetch if Puppeteer launch fails.
 * Uses an in-memory cache.
 * @param url The URL to fetch.
 * @returns A promise that resolves to an object containing the page data or an error message.
 */
export async function retrievePageContent(url: string): Promise<PageContentResult> {
  const cacheKey = generateCacheKey('pageContent', url);
  const cachedEntry = cache.get(cacheKey);

  if (cachedEntry && (Date.now() - cachedEntry.timestamp < CACHE_TTL)) {
    console.log(`[Service/PageRetriever] Cache hit for URL: ${url}`);
    return { ...(cachedEntry.data as PageContentResult), retrievedFromCache: true };
  }
  console.log(`[Service/PageRetriever] Cache miss or stale for URL: ${url}.`);

  let browser: Browser | null = null;
  try {
    console.log(`[Service/PageRetriever] Attempting to fetch with Puppeteer for URL: ${url}...`);
    browser = await launchBrowser(); 

    const page: Page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 TechDetective/1.0');
    await page.setExtraHTTPHeaders({
      'Accept-Language': 'en-US,en;q=0.9'
    });

    console.log(`[Service/PageRetriever] Navigating to URL (Puppeteer): ${url}`);
    const response = await page.goto(url, {
      waitUntil: 'networkidle0', 
      timeout: 30000, 
    });

    if (!response) {
      throw new Error('Navigation failed, no response received from page.goto() (Puppeteer).');
    }
    
    const responseHeadersRaw = response.headers(); 
    const responseHeaders: Record<string, string | string[]> = {};
    for (const key in responseHeadersRaw) {
        responseHeaders[key.toLowerCase()] = responseHeadersRaw[key];
    }
    
    let setCookieHeaderValues: string[] = [];
    const setCookieRaw = response.headers()['set-cookie'];
    if (setCookieRaw) {
      setCookieHeaderValues = Array.isArray(setCookieRaw) ? setCookieRaw : [setCookieRaw];
    }

    const status = response.status();
    let htmlContent: string | null;

    if (!response.ok()) {
      const errorText = `HTTP error ${status} ${response.statusText()}`;
      console.warn(`[Service/PageRetriever] Failed to fetch URL ${url} (Puppeteer): ${errorText}`);
      try {
        htmlContent = await page.content(); 
      } catch (contentError) {
        htmlContent = null;
        console.warn(`[Service/PageRetriever] Could not get page content on error for ${url} (Puppeteer):`, contentError);
      }
      const result: PageContentResult = {
        html: htmlContent,
        error: `Failed to fetch (Puppeteer): ${errorText}`,
        status: status,
        headers: responseHeaders,
        setCookieStrings: setCookieHeaderValues,
        finalUrl: page.url(),
        fetchMethod: 'puppeteer',
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
      fetchMethod: 'puppeteer',
      retrievedFromCache: false,
    };
    cache.set(cacheKey, { data: successResult, timestamp: Date.now() });
    return successResult;

  } catch (error: any) {
    let detailedErrorMessage = error.message || 'An unknown error occurred during Puppeteer fetching.';
     if (error.name === 'TimeoutError') {
      detailedErrorMessage = `Navigation timed out for ${url} (Puppeteer). The page might be too slow, complex, or unreachable.`;
    }

    // Check if it's a browser launch failure to initiate fallback
    if (detailedErrorMessage.startsWith('Failed to launch browser:')) {
      console.warn(`[Service/PageRetriever] Puppeteer launch failed for ${url}: ${detailedErrorMessage}. Falling back to undici fetch.`);
      const fetchResult = await fetchWithUndici(url);
      // If undici also fails, its error will be in fetchResult.error
      // If successful, cache the fetchResult
      if (!fetchResult.error || fetchResult.html) { // Cache if successfully fetched or got error page html
          cache.set(cacheKey, { data: fetchResult, timestamp: Date.now() });
      }
      return fetchResult;
    }
    
    console.error(`[Service/PageRetriever] Error fetching URL ${url} with Puppeteer (not a launch error):`, detailedErrorMessage);
    const errorResult: PageContentResult = {
      html: null,
      error: detailedErrorMessage,
      finalUrl: url, 
      status: undefined,
      fetchMethod: 'puppeteer', // Still indicates Puppeteer was attempted
      retrievedFromCache: false,
    };
    // Don't cache generic puppeteer errors that aren't launch failures unless specifically needed.
    return errorResult;
  } finally {
    if (browser) {
      console.log('[Service/PageRetriever] Closing browser.');
      try {
          await browser.close();
      } catch (closeError) {
          console.error('[Service/PageRetriever] Error closing browser:', closeError);
      }
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

  const cacheKey = generateCacheKey('robots', robotsUrl);
  const cachedRobots = cache.get(cacheKey);
  if (cachedRobots && (Date.now() - cachedRobots.timestamp < CACHE_TTL)) {
      console.log(`[Service/PageRetriever] Cache hit for robots.txt: ${robotsUrl}`);
      return (cachedRobots.data as { content: string | null }).content;
  }
  console.log('[Service/PageRetriever] Cache miss or stale for robots.txt. Attempting to fetch from:', robotsUrl);


  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000); 

  try {
    const response = await undiciFetch(robotsUrl, {
      // @ts-ignore
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
     if (error.name === 'AbortError' || (error.name === 'TimeoutError') || (error.cause && (error.cause as Error).name === 'TimeoutError')) {
      detailedErrorMessage = `Request for robots.txt timed out for ${baseUrl}.`;
    } else if (error.cause && typeof error.cause === 'object') {
      const cause = error.cause as any; 
      detailedErrorMessage = `Network error fetching robots.txt: ${cause.code || (cause as Error).message || 'Unknown network issue'}.`;
      if (cause.code === 'UND_ERR_CONNECT_TIMEOUT'){
        detailedErrorMessage = `Connection timed out while fetching robots.txt for ${baseUrl}. Check server connectivity and DNS resolution.`;
      }
      // console.error(`[Service/PageRetriever] Fetch robots.txt error cause for URL ${robotsUrl}:`, JSON.stringify(error.cause, Object.getOwnPropertyNames(error.cause)));
    } else if (error.cause) { 
        detailedErrorMessage = `Network error (robots.txt). Cause: ${String(error.cause)}`;
    } else if (error.code) {
        detailedErrorMessage = `Network error (robots.txt): ${error.code}. Please check server connectivity and DNS resolution.`;
    }
    console.warn(`[Service/PageRetriever] Error fetching robots.txt for ${baseUrl}: ${detailedErrorMessage}`);
    return null;
  }
}
