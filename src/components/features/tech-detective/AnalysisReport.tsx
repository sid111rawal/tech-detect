'use client';

import type { AnalyzeWebsiteCodeOutput } from '@/ai/flows/analyze-website-code';
import { TechnologyItem } from './TechnologyItem';
import { ConcernItem } from './ConcernItem';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Shield, ListChecks, AlertOctagon } from 'lucide-react';

interface AnalysisReportProps {
  report: AnalyzeWebsiteCodeOutput;
}

export function AnalysisReport({ report }: AnalysisReportProps) {
  const { detectedTechnologies, securityConcerns } = report;

  return (
    <div className="space-y-8 mt-8">
      <Card className="shadow-xl">
        <CardHeader>
          <div className="flex items-center gap-3 mb-2">
            <ListChecks className="h-8 w-8 text-primary" />
            <CardTitle className="text-2xl">Detected Technologies</CardTitle>
          </div>
          <CardDescription>
            Libraries, frameworks, and other technologies identified on the website.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {detectedTechnologies.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {detectedTechnologies.map((tech, index) => (
                <TechnologyItem key={index} technology={tech} />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>No specific technologies detected with current analysis methods.</p>
            </div>
          )}
        </CardContent>
      </Card>

      <Separator />

      <Card className="shadow-xl">
        <CardHeader>
          <div className="flex items-center gap-3 mb-2">
            <AlertOctagon className="h-8 w-8 text-destructive" />
            <CardTitle className="text-2xl">Potential Security Concerns</CardTitle>
          </div>
          <CardDescription>
            Identified vulnerabilities or security-related issues.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {securityConcerns.length > 0 ? (
            <ul className="space-y-3">
              {securityConcerns.map((concern, index) => (
                <ConcernItem key={index} concern={concern} />
              ))}
            </ul>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>No specific security concerns identified.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
