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
  const rawFormData = {
    url: formData.get('url') as string,
  };

  const validationResult = AnalyzeUrlSchema.safeParse(rawFormData);

  if (!validationResult.success) {
    return {
      message: "Validation failed.",
      error: true,
      fieldErrors: validationResult.error.flatten().fieldErrors,
    };
  }

  try {
    const result = await analyzeWebsiteCode({ url: validationResult.data.url });
    if (result.detectedTechnologies.length === 0 && result.securityConcerns.length === 0) {
       return { 
        message: "Analysis complete. No specific technologies or security concerns detected with current methods.",
        analysisResult: result,
       };
    }
    return { 
      message: "Analysis successful!",
      analysisResult: result,
    };
  } catch (error) {
    console.error("Analysis error:", error);
    return {
      message: "An error occurred during analysis. Please try again.",
      error: true,
    };
  }
}
