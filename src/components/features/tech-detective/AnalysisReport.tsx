'use client';

import type { WebsiteAnalysisResult } from '@/services/website-analysis';
import { TechnologyItem } from './TechnologyItem';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Shield, ListChecks, Square, DatabaseZap, Shuffle } from 'lucide-react'; 

interface AnalysisReportProps {
  report: WebsiteAnalysisResult;
}

export function AnalysisReport({ report }: AnalysisReportProps) {
  const { detectedTechnologies } = report;

  return (
    <div className="space-y-8 mt-8">
      <Card className="shadow-xl">
        <CardHeader>
          <div className="flex items-center gap-3 mb-2">
            <ListChecks className="h-8 w-8 text-primary" />
            <CardTitle className="text-2xl">Detected Technologies</CardTitle>
          </div>
          <CardDescription>
            {report.analysisSummary || 'Libraries, frameworks, and other technologies identified on the website.'}
            {(report.finalUrl && report.finalUrl !== report.analysisSummary.split(" ")[2] && !report.analysisSummary.includes(report.finalUrl)) && ( 
                 <span className="block text-xs text-muted-foreground mt-1">Analyzed URL: {report.finalUrl} (Status: {report.status || 'N/A'})</span>
            )}
            {report.retrievedFromCache && (
                <span className="block text-xs text-accent mt-1 flex items-center">
                    <DatabaseZap className="h-3 w-3 mr-1" /> Results retrieved from cache.
                </span>
            )}
            {report.fetchMethod && (
                 <span className="block text-xs text-muted-foreground mt-1 flex items-center">
                    <Shuffle className="h-3 w-3 mr-1" /> Content fetched using: {report.fetchMethod}.
                </span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {detectedTechnologies.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {detectedTechnologies.map((tech, index) => (
                <TechnologyItem key={`${tech.technology}-${index}`} technology={tech} />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>No specific technologies detected with current analysis methods.</p>
               {report.error && <p className="text-sm text-destructive mt-2">{report.error}</p>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
