import Image from 'next/image';
import Link from 'next/link';
import siteLogo from '@/images/image.png'; // Import the logo
import { siteConfig } from '@/config/site';

export function Header() {
  return (
    <header className="py-6 px-4 md:px-6 bg-card border-b">
      <div className="container mx-auto flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <Image 
            src={siteLogo} 
            alt={`${siteConfig.name} Logo`}
            width={32} 
            height={32} 
            className="h-8 w-8 text-primary" 
          />
          <h1 className="text-2xl font-bold text-primary">{siteConfig.name}</h1>
        </Link>
        {/* Future navigation items can go here */}
      </div>
    </header>
  );
}
