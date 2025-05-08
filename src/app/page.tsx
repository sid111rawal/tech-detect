'use client';

import { useState, useEffect } from 'react';
import { Header } from '@/components/layout/Header';
import { UrlInputForm } from '@/components/features/tech-detective/UrlInputForm';
import { AnalysisReport } from '@/components/features/tech-detective/AnalysisReport';
import { LoadingState } from '@/components/features/tech-detective/LoadingState';
import { handleAnalyzeWebsite, type FormState } from './actions';
import type { WebsiteAnalysisResult } from '@/services/website-analysis';
import Image from 'next/image';

export default function Home() {
  const [analysisResult, setAnalysisResult] = useState<WebsiteAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [displayWelcome, setDisplayWelcome] = useState(true);

  const handleSetAnalysisResult = (result: FormState['analysisResult'] | null) => {
    setAnalysisResult(result || null);
    if (result || isLoading) {
      setDisplayWelcome(false);
    }
  };
  
  useEffect(() => {
    if (isLoading || analysisResult) {
      setDisplayWelcome(false);
    } else {
      setDisplayWelcome(true);
    }
  }, [isLoading, analysisResult]);

  return (
    <div className="flex flex-col min-h-screen bg-background">
      <Header />
      <main className="flex-grow container mx-auto px-4 py-8 md:py-12 flex flex-col items-center">
        <div className="w-full max-w-4xl">
          <div className="text-center mb-10">
            <Image 
              src="https://picsum.photos/seed/techdetectivemain/600/250" 
              alt="Abstract technology background representing web analysis"
              data-ai-hint="technology abstract"
              width={600} 
              height={250} 
              className="rounded-lg mx-auto mb-6 shadow-xl border border-border"
              priority
            />
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-3">
              Uncover Hidden Web Technologies
            </h2>
            <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
              Tech Detective uses advanced analysis to identify libraries, frameworks, and potential security risks on any website.
              Gain deeper insights into what powers the web.
            </p>
          </div>

          <UrlInputForm 
            onAnalyze={handleAnalyzeWebsite} 
            setAnalysisResult={handleSetAnalysisResult}
            setIsLoading={setIsLoading}
          />

          {isLoading && (
            <div className="mt-10 w-full">
              <LoadingState />
            </div>
          )}

          {!isLoading && analysisResult && (
            <div className="mt-10 w-full">
              <AnalysisReport report={analysisResult} />
            </div>
          )}
          
          {displayWelcome && !isLoading && !analysisResult && (
             <div className="mt-12 text-center p-8 bg-card rounded-xl shadow-lg border border-border/80">
                <Image 
                  src="https://picsum.photos/seed/startanalysishero/400/200" 
                  alt="Illustration depicting data investigation and web technology icons"
                  data-ai-hint="data investigation"
                  width={400} 
                  height={200} 
                  className="rounded-lg mx-auto mb-6 opacity-90 shadow-md"
                />
               <h3 className="text-2xl font-semibold text-foreground mb-2">Ready to Investigate?</h3>
               <p className="text-muted-foreground text-md max-w-md mx-auto">
                 Enter a website URL above to begin your deep dive into its technology stack and security posture.
               </p>
             </div>
          )}
        </div>
      </main>
      <footer className="py-8 text-center text-muted-foreground text-sm border-t border-border/50 mt-auto">
        <p>&copy; {new Date().getFullYear()} Tech Detective. All rights reserved.</p>
      </footer>
    </div>
  );
}