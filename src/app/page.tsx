
'use client';

import { useState, useEffect } from 'react';
import { Header } from '@/components/layout/Header';
import { UrlInputForm } from '@/components/features/tech-detective/UrlInputForm';
import { AnalysisReport } from '@/components/features/tech-detective/AnalysisReport';
import { LoadingState } from '@/components/features/tech-detective/LoadingState';
import { handleAnalyzeWebsite, type FormState } from './actions';
import type { WebsiteAnalysisResult } from '@/services/website-analysis';
import Image from 'next/image';
import siteImage from '@/images/image.png';

export default function Home() {
  const [analysisResult, setAnalysisResult] = useState<WebsiteAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showIntro, setShowIntro] = useState(true);

  const handleSetAnalysisResult = (result: FormState['analysisResult'] | null) => {
    setAnalysisResult(result || null);
    if (result || isLoading) {
      setShowIntro(false);
    }
  };
  
  useEffect(() => {
    if (isLoading) {
      setShowIntro(false);
    }
  }, [isLoading]);


  return (
    <div className="flex flex-col min-h-screen bg-background">
      <Header />
      <main className="flex-grow container mx-auto px-4 py-8 md:py-12 flex flex-col items-center">
        <div className="w-full max-w-4xl">
          <div className="text-center mb-10">
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-3">
              Detect What Powers the Web — Both Visible and Hidden
            </h2>
            <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
              Tech Detective is a proof-of-concept tool designed to analyze websites and uncover the technologies they use—both surface-level and deeply embedded. This POC is actively evolving to identify frameworks, libraries, runtime fingerprints, and even hidden scripts or infrastructure clues.
            </p>
          </div>
          
          <div className="text-center mb-6">
            <p className="text-lg font-semibold text-accent">
              🎯 Prototype Preview: Not all tech leaves visible traces. Let’s find out what’s hiding behind the scenes.
            </p>
          </div>

          <UrlInputForm 
            onAnalyze={handleAnalyzeWebsite} 
            setAnalysisResult={handleSetAnalysisResult}
            setIsLoading={setIsLoading}
          />

          {showIntro && (
            <div className="mt-12 text-center p-8 bg-card rounded-xl shadow-lg border border-border/80">
              <Image
                src={siteImage}
                alt="Tech exploration graphic"
                width={128}
                height={128}
                className="mx-auto mb-6 h-32 w-32 object-contain"
                data-ai-hint="technology abstract"
              />
              <h3 className="text-xl font-semibold text-foreground mb-2">Ready to Investigate?</h3>
              <p className="text-muted-foreground">
                Enter a URL above to begin your web technology analysis.
              </p>
            </div>
          )}

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
          
        </div>
      </main>
      <footer className="py-8 text-center text-muted-foreground text-sm border-t border-border/50 mt-auto">
        <p>&copy; {new Date().getFullYear()} Tech Detective. All rights reserved.</p>
        <p className="mt-2">
          <span className="font-bold">Developed by <a href="https://sidrawal.netlify.app/" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">Sid</a> ❤️</span>
        </p>
      </footer>
    </div>
  );
}
