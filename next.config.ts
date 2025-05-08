
import type {NextConfig} from 'next';

const nextConfig: NextConfig = {
  /* config options here */
  typescript: {
    // !! WARN !!
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'picsum.photos',
        port: '',
        pathname: '/**',
      },
    ],
    // This allows the Next.js Image component to optimize images
    // served from the `src` directory if they were not statically imported.
    // For static imports like `import siteImage from '../../../images/image.png';`,
    // this is often handled automatically. Adding this makes it more explicit
    // if dynamic paths from `src` were ever used, though not typical.
    // However, for static imports, this section might not be strictly necessary.
    // The primary mechanism for local images is placing them in the `public` folder
    // or statically importing them from `src`.
    // Since we are statically importing, it should work.
    // No changes to remotePatterns are strictly needed for static imports from `src`.
    // Keeping this minimal as static imports from `src` are the primary mechanism.
  },
};

export default nextConfig;
