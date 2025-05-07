import { Loader2 } from 'lucide-react';

export function LoadingState() {
  return (
    <div className="flex flex-col items-center justify-center space-y-4 p-12 my-8 bg-card rounded-lg shadow-md">
      <Loader2 className="h-16 w-16 animate-spin text-primary" />
      <p className="text-xl font-medium text-foreground">Analyzing Website...</p>
      <p className="text-sm text-muted-foreground">This may take a few moments. Please wait.</p>
    </div>
  );
}
