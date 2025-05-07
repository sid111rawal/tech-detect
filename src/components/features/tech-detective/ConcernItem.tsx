'use client';

import { AlertTriangle } from "lucide-react";

interface ConcernItemProps {
  concern: string;
}

export function ConcernItem({ concern }: ConcernItemProps) {
  return (
    <li className="flex items-start gap-3 p-3 bg-muted/30 rounded-md border border-dashed border-destructive/50">
      <AlertTriangle className="h-5 w-5 text-destructive flex-shrink-0 mt-0.5" />
      <p className="text-sm text-destructive-foreground">{concern}</p>
    </li>
  );
}
