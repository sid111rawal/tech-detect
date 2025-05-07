
'use server';

import { retrievePageContent } from '@/services/page-retriever';
import { detectTechnologies, type DetectedTechnologyInfo } from '@/lib/signatures';

/**
 * Represents the analysis result of a website.
 */
export type WebsiteAnalysisResult = {
  detectedTechnologies: DetectedTechnologyInfo[];
  analysisSummary: string;
  error?: string;
  finalUrl?: string;
  status?: number;
};

/**
 * Analyzes a website to detect technologies using signature-based methods.
 *
 * @param url The URL of the website to analyze.
 * @returns A promise that resolves to a WebsiteAnalysisResult object.
 */
export async function analyzeWebsite(url: string): Promise<WebsiteAnalysisResult> {
  console.log('[Service/WebsiteAnalysis] Starting analysis for URL:', url);
  const pageData = await retrievePageContent(url);

  if (pageData.error || !pageData.html) {
    const errorMessage = pageData.error || 'No HTML content found.';
    console.warn(`[Service/WebsiteAnalysis] Failed to retrieve content from ${url}: ${errorMessage}`);
    return {
      detectedTechnologies: [],
      analysisSummary: `Failed to retrieve content from ${url}. ${errorMessage}`,
      error: errorMessage,
      finalUrl: pageData.finalUrl,
      status: pageData.status,
    };
  }

  try {
    console.log(`[Service/WebsiteAnalysis] Retrieved content for ${pageData.finalUrl || url}, status: ${pageData.status}. Detecting technologies...`);
    const detectedSignatureTechnologies = await detectTechnologies(pageData, pageData.finalUrl || url);
    console.log(`[Service/WebsiteAnalysis] Signature detection complete for ${pageData.finalUrl || url}. Found ${detectedSignatureTechnologies.length} technologies.`);

    let summary = `Signature-based analysis of ${pageData.finalUrl || url} complete. `;
    if (detectedSignatureTechnologies.length > 0) {
      summary += `Detected ${detectedSignatureTechnologies.length} potential technologies.`;
    } else {
      summary += "No specific technologies detected with current signature-based methods.";
    }
    
    // For debugging, log detected technologies
    // console.log("[Service/WebsiteAnalysis] Detected technologies:", JSON.stringify(detectedSignatureTechnologies, null, 2));


    return {
      detectedTechnologies: detectedSignatureTechnologies,
      analysisSummary: summary,
      finalUrl: pageData.finalUrl,
      status: pageData.status,
    };
  } catch (e: any) {
    console.error(`[Service/WebsiteAnalysis] Error during signature detection for ${url}:`, e);
    return {
      detectedTechnologies: [],
      analysisSummary: `An error occurred during signature-based analysis for ${url}: ${e.message}`,
      error: e.message,
      finalUrl: pageData.finalUrl,
      status: pageData.status,
    };
  }
}
