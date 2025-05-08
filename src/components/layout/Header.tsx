import Image from 'next/image';
import Link from 'next/link';
import siteLogo from '@/images/image.png'; // Import the logo

export function Header() {
  return (
    <header className="py-6 px-4 md:px-6 bg-card border-b">
      <div className="container mx-auto flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <Image 
            src={siteLogo} 
            alt="Tech Detective Logo" 
            width={32} // Equivalent to h-8 (8 * 4px = 32px)
            height={32} // Equivalent to w-8 (8 * 4px = 32px)
            className="h-8 w-8 text-primary" // Keep classes for consistency if needed, though size is set by width/height
          />
          <h1 className="text-2xl font-bold text-primary">Tech Detective</h1>
        </Link>
        {/* Future navigation items can go here */}
      </div>
    </header>
  );
}
