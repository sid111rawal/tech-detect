
'use server';

import { z } from 'zod';
import { analyzeWebsiteCode, type AnalyzeWebsiteCodeOutput } from '@/ai/flows/analyze-website-code';

const AnalyzeUrlSchema = z.object({
  url: z.string().url({ message: "Invalid URL format. Please include http:// or https://" }),
});

export type FormState = {
  message: string;
  analysisResult?: AnalyzeWebsiteCodeOutput;
  error?: boolean;
  fieldErrors?: Record<string, string[] | undefined>;
};

export async function handleAnalyzeWebsite(
  prevState: FormState | undefined,
  formData: FormData
): Promise<FormState> {
  console.log('[ActionHandler] handleAnalyzeWebsite called with formData:', formData);
  const rawFormData = {
    url: formData.get('url') as string,
  };
  console.log('[ActionHandler] Raw form data:', rawFormData);

  const validationResult = AnalyzeUrlSchema.safeParse(rawFormData);

  if (!validationResult.success) {
    console.warn('[ActionHandler] Validation failed:', validationResult.error.flatten().fieldErrors);
    return {
      message: "Validation failed.",
      error: true,
      fieldErrors: validationResult.error.flatten().fieldErrors,
    };
  }
  console.log('[ActionHandler] Validation successful. Validated URL:', validationResult.data.url);

  try {
    console.log('[ActionHandler] Calling analyzeWebsiteCode with URL:', validationResult.data.url);
    const result = await analyzeWebsiteCode({ url: validationResult.data.url });
    console.log('[ActionHandler] analyzeWebsiteCode result:', result);

    if (result.detectedTechnologies.length === 0 && result.securityConcerns.length === 0) {
       console.log('[ActionHandler] Analysis complete. No specific technologies or security concerns detected.');
       return { 
        message: "Analysis complete. No specific technologies or security concerns detected with current methods.",
        analysisResult: result,
       };
    }
    console.log('[ActionHandler] Analysis successful with detected items.');
    return { 
      message: "Analysis successful!",
      analysisResult: result,
    };
  } catch (error) {
    console.error("[ActionHandler] Error during analysis:", error);
    let errorMessage = "An error occurred during analysis. Please try again.";
    if (error instanceof Error) {
      errorMessage = error.message;
    }
    return {
      message: `Analysis error: ${errorMessage}`,
      error: true,
    };
  }
}

