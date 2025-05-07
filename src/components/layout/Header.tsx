import { Binary } from 'lucide-react';
import Link from 'next/link';

export function Header() {
  return (
    <header className="py-6 px-4 md:px-6 bg-card border-b">
      <div className="container mx-auto flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <Binary className="h-8 w-8 text-primary" />
          <h1 className="text-2xl font-bold text-primary">Tech Detective</h1>
        </Link>
        {/* Future navigation items can go here */}
      </div>
    </header>
  );
}
