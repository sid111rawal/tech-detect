
'use client';

import { useState, useEffect } from 'react';
import { Header } from '@/components/layout/Header';
import { UrlInputForm } from '@/components/features/tech-detective/UrlInputForm';
import { AnalysisReport } from '@/components/features/tech-detective/AnalysisReport';
import { LoadingState } from '@/components/features/tech-detective/LoadingState';
import { handleAnalyzeWebsite, type FormState } from './actions';
import type { WebsiteAnalysisResult } from '@/services/website-analysis';
import { siteConfig } from '@/config/site';

export default function Home() {
  const [analysisResult, setAnalysisResult] = useState<WebsiteAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSetAnalysisResult = (result: FormState['analysisResult'] | null) => {
    setAnalysisResult(result || null);
  };
  
  return (
    <div className="flex flex-col min-h-screen bg-background">
      <Header />
      <main className="flex-grow container mx-auto px-4 py-8 md:py-12 flex flex-col items-center">
        <div className="w-full max-w-4xl">
          <div className="text-center mb-10">
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-3">
              {siteConfig.tagline}
            </h2>
            <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
              {siteConfig.subTagline}
            </p>
          </div>
          
          <div className="text-center mb-6">
            <p className="text-lg font-semibold text-accent">
              {siteConfig.previewText}
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
          
        </div>
      </main>
      <footer className="py-8 text-center text-muted-foreground text-sm border-t border-border/50 mt-auto">
        <p>&copy; {new Date().getFullYear()} {siteConfig.name}. All rights reserved.</p>
        <p className="mt-2">
          <span className="font-bold">Developed by <a href="https://sidrawal.netlify.app/" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">Sid</a> ❤️</span>
        </p>
      </footer>
    </div>
  );
}

