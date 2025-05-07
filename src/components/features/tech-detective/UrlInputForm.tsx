'use client';

import { useEffect } from 'react';
import { useFormState, useFormStatus } from 'react-dom';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertCircle, Search } from 'lucide-react';
import type { handleAnalyzeWebsite, FormState } from '@/app/actions';
import { useToast } from '@/hooks/use-toast';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';


interface UrlInputFormProps {
  onAnalyze: typeof handleAnalyzeWebsite;
  setAnalysisResult: (result: FormState['analysisResult'] | null) => void;
  setIsLoading: (loading: boolean) => void;
}

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" disabled={pending} className="w-full sm:w-auto bg-accent hover:bg-accent/90 text-accent-foreground">
      {pending ? (
        <>
          <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          Analyzing...
        </>
      ) : (
        <>
          <Search className="mr-2 h-4 w-4" />
          Analyze Website
        </>
      )}
    </Button>
  );
}

export function UrlInputForm({ onAnalyze, setAnalysisResult, setIsLoading }: UrlInputFormProps) {
  const initialState: FormState | undefined = undefined;
  const [state, formAction] = useFormState(onAnalyze, initialState);
  const { toast } = useToast();
  const { pending } = useFormStatus(); // Get pending state for the form overall

  useEffect(() => {
    setIsLoading(pending); // Update loading state based on form submission status
  }, [pending, setIsLoading]);


  useEffect(() => {
    if (state) {
      setIsLoading(false);
      if (state.error) {
        toast({
          variant: "destructive",
          title: "Error",
          description: state.message,
        });
        setAnalysisResult(null);
      } else {
        if (state.message !== "Validation failed.") { // Avoid toast for initial validation messages
             toast({
                title: "Analysis Status",
                description: state.message,
             });
        }
        setAnalysisResult(state.analysisResult ?? null);
      }
    }
  }, [state, toast, setAnalysisResult, setIsLoading]);

  return (
    <Card className="w-full max-w-2xl mx-auto shadow-xl">
      <CardHeader>
        <CardTitle className="text-2xl">Website Technology Analyzer</CardTitle>
        <CardDescription>
          Enter a website URL to detect technologies, frameworks, and potential security concerns.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form action={formAction} className="space-y-6">
          <div className="space-y-2">
            <label htmlFor="url" className="block text-sm font-medium text-foreground">
              Website URL
            </label>
            <Input
              id="url"
              name="url"
              type="url"
              placeholder="e.g., https://example.com"
              required
              className="text-base"
            />
            {state?.fieldErrors?.url && (
              <p className="text-sm text-destructive flex items-center pt-1"> 
                <AlertCircle className="h-4 w-4 mr-1"/> {state.fieldErrors.url.join(', ')}
              </p>
            )}
          </div>
          {state?.error && !state.fieldErrors && (
             <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Analysis Error</AlertTitle>
                <AlertDescription>{state.message}</AlertDescription>
            </Alert>
          )}
          <SubmitButton />
        </form>
      </CardContent>
    </Card>
  );
}
