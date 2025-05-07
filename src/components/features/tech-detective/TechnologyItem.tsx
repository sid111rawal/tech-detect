'use client';

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Code2, ShieldAlert, ShieldCheck, Puzzle } from "lucide-react";
import type { AnalyzeWebsiteCodeOutput } from '@/ai/flows/analyze-website-code';

type Technology = AnalyzeWebsiteCodeOutput['detectedTechnologies'][0];

interface TechnologyItemProps {
  technology: Technology;
}

export function TechnologyItem({ technology }: TechnologyItemProps) {
  const confidencePercentage = Math.round(technology.confidence * 100);

  return (
    <Card className="bg-card/50 hover:shadow-md transition-shadow">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg flex items-center gap-2">
          {technology.isHarmful ? <ShieldAlert className="h-6 w-6 text-destructive" /> : <ShieldCheck className="h-6 w-6 text-green-600" />}
          {technology.technology || "Unknown Technology"}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Confidence:</span>
          <span className="font-medium">{confidencePercentage}%</span>
        </div>
        <Progress value={confidencePercentage} aria-label={`Confidence ${confidencePercentage}%`} className="h-2 [&>div]:bg-accent" />
        
        {technology.isHarmful && (
          <Badge variant="destructive" className="text-xs">Potentially Harmful</Badge>
        )}
        {!technology.isHarmful && (
           <Badge variant="secondary" className="text-xs bg-green-100 text-green-800 border-green-300 dark:bg-green-800 dark:text-green-100 dark:border-green-600">Considered Safe</Badge>
        )}
      </CardContent>
    </Card>
  );
}
