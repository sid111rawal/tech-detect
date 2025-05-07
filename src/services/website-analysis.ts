import { analyzeWebsiteCode, type AnalyzeWebsiteCodeOutput } from '@/ai/flows/analyze-website-code';

/**
 * Represents the analysis result of a website.
 * This is an alias for AnalyzeWebsiteCodeOutput.
 */
export type WebsiteAnalysisResult = AnalyzeWebsiteCodeOutput;

/**
 * Analyzes a website to detect technologies using signature-based methods.
 *
 * @param url The URL of the website to analyze.
 * @returns A promise that resolves to a WebsiteAnalysisResult object.
 */
export async function analyzeWebsite(url: string): Promise<WebsiteAnalysisResult> {
  // Call the analyzeWebsiteCode flow (now non-AI) to get the analysis result.
  const result: AnalyzeWebsiteCodeOutput = await analyzeWebsiteCode({ url });
  return result;
}

