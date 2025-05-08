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
const cache = new Map<string, { data: PageContentResult | { content: string | null }; timestamp: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function generateCacheKey(type: 'pageContent' | 'robots', identifier: string): string {
  return `${type}:v3:${identifier}`; // Incremented version to avoid old cache conflicts
}


async function launchBrowser(): Promise<Browser> {
  try {
    let resolvedExecutablePath: string | undefined;

    // Try @sparticuz/chromium-min first.
    // This is the recommended approach for serverless/constrained environments.
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

    // Fallback for local development if @sparticuz/chromium-min fails AND not in a strict production mode.
    // Note: puppeteer.executablePath() with puppeteer-core usually returns undefined unless full puppeteer is somehow present.
    if (!resolvedExecutablePath && process.env.NODE_ENV !== 'production') {
      console.log('[Service/PageRetriever] Attempting fallback to puppeteer.executablePath() for local development...');
      try {
        const puppeteerDefaultPath = puppeteer.executablePath(); // For puppeteer-core, this is often undefined.
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
      executablePath: resolvedExecutablePath, // Must be a valid string path
      headless: chromium.headless, // Recommended to use chromium.headless
      ignoreHTTPSErrors: true,
    });
    console.log('[Service/PageRetriever] Browser launched successfully.');
    return browser;

  } catch (error) {
    console.error('[Service/PageRetriever] Error in launchBrowser:', error);
    let errorMessage = (error instanceof Error) ? error.message : String(error);
    // Make the error message more specific if it's the "path" argument error
    if (errorMessage.toLowerCase().includes("path argument must be of type string")) {
        errorMessage = "Chromium executable path was invalid or undefined. Ensure it's a valid string. Original error: " + errorMessage;
    }
    throw new Error(`Failed to launch browser: ${errorMessage}`);
  }
}


/**
 * Retrieves the HTML content, headers, and cookies of a given URL using Puppeteer.
 * Uses an in-memory cache to avoid re-fetching recently accessed URLs.
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
  console.log(`[Service/PageRetriever] Cache miss or stale for URL: ${url}. Attempting to fetch with Puppeteer...`);

  let browser: Browser | null = null;
  try {
    browser = await launchBrowser(); // launchBrowser now throws if it can't return a Browser

    const page: Page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 TechDetective/1.0');
    await page.setExtraHTTPHeaders({
      'Accept-Language': 'en-US,en;q=0.9'
    });

    console.log(`[Service/PageRetriever] Navigating to URL: ${url}`);
    const response = await page.goto(url, {
      waitUntil: 'networkidle0', 
      timeout: 30000, 
    });

    if (!response) {
      // This case should ideally be rare if page.goto resolves, but good for robustness
      throw new Error('Navigation failed, no response received from page.goto().');
    }
    
    const responseHeaders: Record<string, string | string[]> = {};
    const rawHeaders = response.headers(); 
    for (const key in rawHeaders) {
        responseHeaders[key.toLowerCase()] = rawHeaders[key];
    }

    // Handle Set-Cookie headers correctly
    // Puppeteer's response.headers() gives an object where header names are lowercase.
    // 'set-cookie' can be an array of strings or a single string.
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
      detailedErrorMessage = `Navigation timed out for ${url}. The page might be too slow, complex, or unreachable.`;
    }
    
    const errorResult: PageContentResult = {
      html: null,
      error: detailedErrorMessage, // This will now include the more specific "Failed to launch browser" message if that was the cause
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
    const response = await fetch(robotsUrl, {
      // @ts-ignore Node.js fetch supports AbortSignal directly
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
      console.error(`[Service/PageRetriever] Fetch robots.txt error cause for URL ${robotsUrl}:`, JSON.stringify(error.cause, Object.getOwnPropertyNames(error.cause)));
    } else if (error.cause) { 
        detailedErrorMessage = `Network error (robots.txt). Cause: ${String(error.cause)}`;
    }
    console.warn(`[Service/PageRetriever] Error fetching robots.txt for ${baseUrl}: ${detailedErrorMessage}`);
    return null;
  }
}
