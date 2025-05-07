import { analyzeWebsiteCode, type AnalyzeWebsiteCodeOutput } from '@/ai/flows/analyze-website-code';

/**
 * Represents the analysis result of a website.
 * This is now an alias for AnalyzeWebsiteCodeOutput to ensure type consistency.
 */
export type WebsiteAnalysisResult = AnalyzeWebsiteCodeOutput;

/**
 * Analyzes a website to detect technologies and potential security concerns.
 *
 * @param url The URL of the website to analyze.
 * @returns A promise that resolves to a WebsiteAnalysisResult object (which is AnalyzeWebsiteCodeOutput).
 */
export async function analyzeWebsite(url: string): Promise<WebsiteAnalysisResult> {
  // Call the analyzeWebsiteCode flow to get the actual analysis result.
  const result: AnalyzeWebsiteCodeOutput = await analyzeWebsiteCode({ url });
  return result;
}

