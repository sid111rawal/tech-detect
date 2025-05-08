'use server';

import { retrievePageContent, type PageContentResult } from '@/services/page-retriever';
import { detectTechnologies, type DetectedTechnologyInfo, type RedFlag } from '@/lib/signatures';
import { getIpAddress, getSslCertificateInfo, type SslCertificateInfo } from './network-info';
import { URL } from 'url';


/**
 * Represents the analysis result of a website.
 */
export type WebsiteAnalysisResult = {
  detectedTechnologies: DetectedTechnologyInfo[];
  analysisSummary: string;
  error?: string;
  finalUrl?: string;
  status?: number;
  retrievedFromCache?: boolean;
  fetchMethod?: 'puppeteer' | 'fetch';
  ipAddress?: string | null;
  hostingInfo?: string | null; // Simplified for now
  sslCertificateInfo?: SslCertificateInfo | null;
  redFlags?: RedFlag[];
};

/**
 * Analyzes a website to detect technologies using signature-based methods.
 *
 * @param url The URL of the website to analyze.
 * @returns A promise that resolves to a WebsiteAnalysisResult object.
 */
export async function analyzeWebsite(url: string): Promise<WebsiteAnalysisResult> {
  console.log('[Service/WebsiteAnalysis] Starting analysis for URL:', url);
  
  let hostname: string;
  try {
    const parsedUrl = new URL(url);
    hostname = parsedUrl.hostname;
  } catch (e: any) {
    console.warn(`[Service/WebsiteAnalysis] Invalid URL format: ${url}`, e.message);
    return {
      detectedTechnologies: [],
      analysisSummary: `Invalid URL format: ${url}. Please ensure it includes http:// or https://.`,
      error: `Invalid URL: ${e.message}`,
      fetchMethod: undefined, // Or a specific value if known at this point
    };
  }

  // Fetch IP and SSL info concurrently with page content retrieval
  const [pageData, ipAddress, sslCertificateInfo] = await Promise.all([
    retrievePageContent(url),
    getIpAddress(hostname),
    getSslCertificateInfo(hostname)
  ]);

  if (pageData.error || !pageData.html) {
    const errorMessage = pageData.error || 'No HTML content found to analyze.';
    console.warn(`[Service/WebsiteAnalysis] Failed to retrieve content from ${url} (using ${pageData.fetchMethod || 'unknown method'}): ${errorMessage}`);
    return {
      detectedTechnologies: [],
      analysisSummary: `Failed to retrieve content from ${url} (using ${pageData.fetchMethod || 'N/A'}). ${errorMessage}`,
      error: errorMessage,
      finalUrl: pageData.finalUrl,
      status: pageData.status,
      retrievedFromCache: pageData.retrievedFromCache,
      fetchMethod: pageData.fetchMethod,
      ipAddress,
      sslCertificateInfo,
      hostingInfo: null, // Could attempt to infer from IP later or detected CDNs
      redFlags: [],
    };
  }

  try {
    console.log(`[Service/WebsiteAnalysis] Retrieved content for ${pageData.finalUrl || url} (using ${pageData.fetchMethod}), status: ${pageData.status}${pageData.retrievedFromCache ? ' (from cache)' : ''}. Detecting technologies...`);
    
    const { technologies: detectedSignatureTechnologies, redFlags } = await detectTechnologies(pageData, pageData.finalUrl || url, sslCertificateInfo);
    console.log(`[Service/WebsiteAnalysis] Signature detection complete for ${pageData.finalUrl || url}. Found ${detectedSignatureTechnologies.length} technologies and ${redFlags.length} red flags.`);

    let summary = `Analysis of ${pageData.finalUrl || url} (using ${pageData.fetchMethod}) complete${pageData.retrievedFromCache ? ' (content from cache)' : ''}. `;
    if (detectedSignatureTechnologies.length > 0) {
      summary += `Detected ${detectedSignatureTechnologies.length} potential technologies. `;
    } else {
      summary += "No specific technologies detected with current methods. ";
    }
    if (redFlags.length > 0) {
      summary += `Identified ${redFlags.length} potential red flags.`;
    }


    // Infer basic hosting info from detected CDNs or hosting provider signatures
    let inferredHostingInfo: string | null = null;
    const hostingTech = detectedSignatureTechnologies.find(
      tech => tech.category === 'hosting_providers' || tech.category === 'reverse_proxies' && (tech.technology.includes('Cloudflare') || tech.technology.includes('AWS') || tech.technology.includes('Google Cloud'))
    );
    if (hostingTech) {
      inferredHostingInfo = hostingTech.technology;
    }


    return {
      detectedTechnologies: detectedSignatureTechnologies,
      analysisSummary: summary,
      finalUrl: pageData.finalUrl,
      status: pageData.status,
      retrievedFromCache: pageData.retrievedFromCache,
      fetchMethod: pageData.fetchMethod,
      ipAddress,
      hostingInfo: inferredHostingInfo,
      sslCertificateInfo,
      redFlags,
    };
  } catch (e: any) {
    console.error(`[Service/WebsiteAnalysis] Error during signature detection for ${url}:`, e);
    return {
      detectedTechnologies: [],
      analysisSummary: `An error occurred during signature-based analysis for ${url}: ${e.message}`,
      error: e.message,
      finalUrl: pageData.finalUrl,
      status: pageData.status,
      retrievedFromCache: pageData.retrievedFromCache,
      fetchMethod: pageData.fetchMethod,
      ipAddress,
      hostingInfo: null,
      sslCertificateInfo,
      redFlags: [{ type: 'Analysis Error', message: `Error during analysis: ${e.message}`, severity: 'high' }],
    };
  }
}
