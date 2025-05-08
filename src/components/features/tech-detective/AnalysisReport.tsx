'use client';

import type { WebsiteAnalysisResult } from '@/services/website-analysis';
import { TechnologyItem } from './TechnologyItem';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Shield, ListChecks, Square, DatabaseZap, Shuffle, AlertTriangle, Server, Globe, ShieldCheck, ShieldOff, CalendarDays, FingerprintIcon } from 'lucide-react'; 
import { Badge } from '@/components/ui/badge';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

interface AnalysisReportProps {
  report: WebsiteAnalysisResult;
}

const getSeverityColor = (severity: 'low' | 'medium' | 'high' | 'critical') => {
  switch (severity) {
    case 'low': return 'bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-700 dark:text-yellow-100 dark:border-yellow-500';
    case 'medium': return 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-700 dark:text-orange-100 dark:border-orange-500';
    case 'high': return 'bg-red-100 text-red-800 border-red-300 dark:bg-red-700 dark:text-red-100 dark:border-red-500';
    case 'critical': return 'bg-red-200 text-red-900 border-red-400 dark:bg-red-800 dark:text-red-50 dark:border-red-600 font-bold';
    default: return 'bg-gray-100 text-gray-800 border-gray-300 dark:bg-gray-700 dark:text-gray-100 dark:border-gray-500';
  }
};

export function AnalysisReport({ report }: AnalysisReportProps) {
  const { detectedTechnologies, ipAddress, hostingInfo, sslCertificateInfo, redFlags } = report;

  const isSslValid = sslCertificateInfo && !sslCertificateInfo.error && sslCertificateInfo.validTo && new Date(sslCertificateInfo.validTo) > new Date();


  return (
    <div className="space-y-8 mt-8">
      {/* Summary and Red Flags Section */}
      <Card className="shadow-lg">
        <CardHeader>
            <div className="flex items-center gap-3 mb-2">
                <Server className="h-8 w-8 text-primary" />
                <CardTitle className="text-2xl">Website Overview</CardTitle>
            </div>
             <CardDescription>
                Summary of the analyzed website, including IP address, hosting, and SSL status.
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
        <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-md">
                    <Globe className="h-5 w-5 text-primary"/>
                    <strong>IP Address:</strong>
                    <span>{ipAddress || 'N/A'}</span>
                </div>
                <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-md">
                    <Server className="h-5 w-5 text-primary"/>
                    <strong>Hosting Provider:</strong>
                    <span>{hostingInfo || 'N/A - Could not determine'}</span>
                </div>
            </div>

            {sslCertificateInfo && (
                <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="ssl-info">
                    <AccordionTrigger className="text-base font-semibold hover:no-underline">
                        <div className="flex items-center gap-2">
                        {isSslValid ? <ShieldCheck className="h-5 w-5 text-green-600" /> : <ShieldOff className="h-5 w-5 text-destructive" />}
                        SSL Certificate Status
                        </div>
                    </AccordionTrigger>
                    <AccordionContent className="text-sm space-y-2 pt-2">
                    {sslCertificateInfo.error ? (
                        <p className="text-destructive flex items-center gap-1"><AlertTriangle className="h-4 w-4" /> {sslCertificateInfo.error}</p>
                    ) : (
                        <>
                        <p><strong>Subject:</strong> {sslCertificateInfo.subject?.CN || 'N/A'} (Org: {sslCertificateInfo.subject?.O || 'N/A'})</p>
                        <p><strong>Issuer:</strong> {sslCertificateInfo.issuer?.CN || 'N/A'} (Org: {sslCertificateInfo.issuer?.O || 'N/A'})</p>
                        <div className="flex items-center gap-1">
                            <CalendarDays className="h-4 w-4 text-muted-foreground"/>
                            <strong>Valid From:</strong> {sslCertificateInfo.validFrom ? new Date(sslCertificateInfo.validFrom).toLocaleDateString() : 'N/A'}
                        </div>
                        <div className="flex items-center gap-1">
                           <CalendarDays className="h-4 w-4 text-muted-foreground"/>
                           <strong>Valid To:</strong> {sslCertificateInfo.validTo ? new Date(sslCertificateInfo.validTo).toLocaleDateString() : 'N/A'}
                           {sslCertificateInfo.validTo && new Date(sslCertificateInfo.validTo) < new Date() && <Badge variant="destructive" className="ml-2">Expired</Badge>}
                           {sslCertificateInfo.validTo && new Date(sslCertificateInfo.validTo) > new Date() && new Date(sslCertificateInfo.validTo) < new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) && <Badge variant="outline" className="ml-2 border-yellow-500 text-yellow-700">Expiring Soon</Badge>}
                        </div>
                        <p className="flex items-center gap-1 truncate"><FingerprintIcon className="h-4 w-4 text-muted-foreground" /> <strong>Fingerprint:</strong> <code className="text-xs bg-muted px-1 rounded-sm">{sslCertificateInfo.fingerprint?.substring(0, 40) || 'N/A'}...</code></p>
                        </>
                    )}
                    </AccordionContent>
                </AccordionItem>
                </Accordion>
            )}

            {redFlags && redFlags.length > 0 && (
            <Accordion type="single" collapsible className="w-full" defaultValue="red-flags">
                <AccordionItem value="red-flags">
                    <AccordionTrigger className="text-base font-semibold hover:no-underline text-destructive">
                        <div className="flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5 text-destructive" />
                        Potential Red Flags ({redFlags.length})
                        </div>
                    </AccordionTrigger>
                    <AccordionContent className="pt-2">
                        <ul className="space-y-3">
                        {redFlags.map((flag, index) => (
                            <li key={index} className={`p-3 border-l-4 rounded-r-md ${getSeverityColor(flag.severity)}`}>
                            <p className="font-semibold">{flag.type}</p>
                            <p className="text-sm">{flag.message}</p>
                            {flag.recommendation && <p className="text-xs mt-1 opacity-80"><em>Recommendation: {flag.recommendation}</em></p>}
                            </li>
                        ))}
                        </ul>
                    </AccordionContent>
                </AccordionItem>
            </Accordion>
            )}
             {!redFlags || redFlags.length === 0 && (
                 <div className="p-4 text-center text-green-700 bg-green-50 border border-green-200 rounded-md flex items-center justify-center gap-2">
                    <ShieldCheck className="h-5 w-5"/>
                    <span>No major red flags identified based on current checks.</span>
                </div>
            )}
        </CardContent>
      </Card>

      {/* Detected Technologies Section */}
      <Card className="shadow-xl">
        <CardHeader>
          <div className="flex items-center gap-3 mb-2">
            <ListChecks className="h-8 w-8 text-primary" />
            <CardTitle className="text-2xl">Detected Technologies</CardTitle>
          </div>
          <CardDescription>
            {report.analysisSummary || 'Libraries, frameworks, and other technologies identified on the website.'}
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
