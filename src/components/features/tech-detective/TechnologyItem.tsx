
'use client';

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Code2, ShieldAlert, ShieldCheck, Puzzle, Info, LinkIcon, FileText, SearchCode, Package } from "lucide-react";
import type { DetectedTechnologyInfo as DetectedTechnology } from '@/lib/signatures'; // Changed import
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import Image from 'next/image';
import { siteConfig } from "@/config/site";

interface TechnologyItemProps {
  technology: DetectedTechnology;
}

export function TechnologyItem({ technology }: TechnologyItemProps) {
  const confidencePercentage = Math.round((technology.confidence || 0)); // Confidence is already 0-100

  const getIcon = () => {
    if (technology.icon) {
      // Assuming icons are in public/icons/ and are SVGs named like "React.svg"
      // This path needs to be resolvable by Next.js Image component
      const iconPath = `/icons/${technology.icon}`; 
      return (
        <Image 
          src={iconPath} 
          alt={`${technology.technology} icon`} 
          width={20} 
          height={20}
          className="mr-2 flex-shrink-0"
          onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} // Hide if image fails to load
        />
      );
    }
    // Fallback Lucide icon based on category or a generic one
    if (technology.category?.toLowerCase().includes('security')) return <ShieldAlert className="h-5 w-5 text-destructive flex-shrink-0" />;
    if (technology.category?.toLowerCase().includes('framework') || technology.category?.toLowerCase().includes('library')) return <Code2 className="h-5 w-5 text-blue-500 flex-shrink-0" />;
    return <Package className="h-5 w-5 text-muted-foreground flex-shrink-0" />;
  };


  return (
    <Card className="bg-card/70 hover:shadow-lg transition-shadow duration-200 flex flex-col">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between mb-1">
          <CardTitle className="text-lg flex items-center gap-1 truncate" title={technology.technology}>
            {getIcon()}
            {technology.isHarmful && !technology.category?.toLowerCase().includes('security') ? <ShieldAlert className="h-5 w-5 text-destructive flex-shrink-0" /> : null}
            {!technology.isHarmful && technology.isHarmful !== undefined && !technology.category?.toLowerCase().includes('security') ? <ShieldCheck className="h-5 w-5 text-green-600 flex-shrink-0" /> : null}
            <span className="truncate">{technology.technology || "Unknown Technology"}</span>
          </CardTitle>
          {technology.version && (
            <Badge variant="outline" className="text-xs whitespace-nowrap ml-2 shrink-0">v{technology.version}</Badge>
          )}
        </div>
        {technology.category && (
            <CardDescription className="text-xs flex items-center gap-1">
                <Puzzle className="h-3 w-3"/> {technology.category}
            </CardDescription>
        )}
      </CardHeader>
      <CardContent className="space-y-3 text-sm flex-grow">
        {siteConfig.showConfidence && (
          <>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Confidence:</span>
              <span className="font-semibold">{confidencePercentage}%</span>
            </div>
            <Progress value={confidencePercentage} aria-label={`Confidence ${confidencePercentage}%`} className="h-2 [&>div]:bg-accent" />
          </>
        )}
        
        {technology.isHarmful && (
          <Badge variant="destructive" className="text-xs w-full justify-center py-1">Potentially Harmful</Badge>
        )}
        {!technology.isHarmful && technology.isHarmful !== undefined && (
           <Badge variant="secondary" className="text-xs w-full justify-center py-1 bg-green-100 text-green-800 border-green-300 dark:bg-green-800 dark:text-green-100 dark:border-green-600">Considered Safe</Badge>
        )}
         {technology.isHarmful === undefined && (
             <Badge variant="outline" className="text-xs w-full justify-center py-1">Harmfulness N/A</Badge>
        )}
      </CardContent>
      {(technology.detectionMethod || technology.matchedValue || technology.website) && (
        <Accordion type="single" collapsible className="w-full text-xs border-t mt-auto">
          <AccordionItem value="item-1" className="border-b-0">
            <AccordionTrigger className="px-6 py-2 text-muted-foreground hover:no-underline">
              <Info className="h-4 w-4 mr-2" /> More Details
            </AccordionTrigger>
            <AccordionContent className="px-6 pb-4 space-y-2 text-xs">
              {technology.detectionMethod && (
                <div className="flex items-start gap-2">
                  <SearchCode className="h-4 w-4 text-muted-foreground flex-shrink-0 mt-0.5" />
                  <div>
                    <strong className="block text-foreground">Detection:</strong>
                    <span className="text-muted-foreground">{technology.detectionMethod}</span>
                  </div>
                </div>
              )}
              {technology.matchedValue && (
                <div className="flex items-start gap-2">
                  <FileText className="h-4 w-4 text-muted-foreground flex-shrink-0 mt-0.5" />
                  <div>
                    <strong className="block text-foreground">Matched:</strong>
                    <code className="text-muted-foreground break-all bg-muted/50 px-1 rounded-sm text-[0.9em]">{technology.matchedValue.length > 100 ? technology.matchedValue.substring(0,97) + "..." : technology.matchedValue}</code>
                  </div>
                </div>
              )}
              {technology.website && (
                <div className="flex items-center gap-2">
                  <LinkIcon className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <div>
                    <strong className="text-foreground">Website:</strong>{' '}
                    <a href={technology.website} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline break-all">
                      {technology.website}
                    </a>
                  </div>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      )}
    </Card>
  );
}
