'use client';

import { useState } from 'react';
import { Header } from '@/components/layout/Header';
import { UrlInputForm } from '@/components/features/tech-detective/UrlInputForm';
import { AnalysisReport } from '@/components/features/tech-detective/AnalysisReport';
import { LoadingState } from '@/components/features/tech-detective/LoadingState';
import { handleAnalyzeWebsite, type FormState } from './actions';
import type { AnalyzeWebsiteCodeOutput } from '@/ai/flows/analyze-website-code';
import Image from 'next/image';

export default function Home() {
  const [analysisResult, setAnalysisResult] = useState<AnalyzeWebsiteCodeOutput | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSetAnalysisResult = (result: FormState['analysisResult'] | null) => {
    setAnalysisResult(result || null);
  };

  return (
    <div className="flex flex-col min-h-screen bg-background">
      <Header />
      <main className="flex-grow container mx-auto px-4 py-8 md:py-12">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <Image 
              src="https://picsum.photos/seed/techdetective/600/300" 
              alt="Abstract technology background"
              data-ai-hint="technology abstract"
              width={600} 
              height={300} 
              className="rounded-lg mx-auto mb-6 shadow-lg"
            />
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4">
              Uncover Hidden Web Technologies
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Tech Detective uses advanced analysis to identify libraries, frameworks, and potential security risks on any website.
              Gain deeper insights into what powers the web.
            </p>
          </div>

          <UrlInputForm 
            onAnalyze={handleAnalyzeWebsite} 
            setAnalysisResult={handleSetAnalysisResult}
            setIsLoading={setIsLoading}
          />

          {isLoading && <LoadingState />}

          {!isLoading && analysisResult && (
            <AnalysisReport report={analysisResult} />
          )}
          
          {!isLoading && !analysisResult && (
             <div className="mt-12 text-center p-8 bg-card rounded-lg shadow-md">
                <Image 
                  src="https://picsum.photos/seed/startanalysis/400/250" 
                  alt="Illustration encouraging analysis"
                  data-ai-hint="data analysis"
                  width={400} 
                  height={250} 
                  className="rounded-lg mx-auto mb-4 opacity-80"
                />
               <h3 className="text-xl font-semibold text-foreground mb-2">Ready to Investigate?</h3>
               <p className="text-muted-foreground">
                 Enter a URL above to begin your web technology analysis.
               </p>
             </div>
          )}
        </div>
      </main>
      <footer className="py-6 text-center text-muted-foreground text-sm border-t">
        <p>&copy; {new Date().getFullYear()} Tech Detective. All rights reserved.</p>
      </footer>
    </div>
  );
}
