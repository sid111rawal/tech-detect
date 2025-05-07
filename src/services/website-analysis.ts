import { analyzeWebsiteCode } from '@/ai/flows/analyze-website-code';

/**
 * Represents the analysis result of a website.
 */
export interface WebsiteAnalysisResult {
  /**
   * A list of detected technologies.
   */
  detectedTechnologies: string[];
  /**
   * A list of potential security concerns.
   */
  securityConcerns: string[];
}

/**
 * Analyzes a website to detect technologies and potential security concerns.
 *
 * @param url The URL of the website to analyze.
 * @returns A promise that resolves to a WebsiteAnalysisResult object.
 */
export async function analyzeWebsite(url: string): Promise<WebsiteAnalysisResult> {
  // Call the analyzeWebsiteCode flow to get the actual analysis result.
  return analyzeWebsiteCode({ url });
}
