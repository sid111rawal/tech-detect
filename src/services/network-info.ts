'use server';

import dns from 'dns';
import tls from 'tls';
import { promisify } from 'util';

const lookup = promisify(dns.lookup);

export interface SslCertificateInfo {
  subject?: Record<string, string>;
  issuer?: Record<string, string>;
  validFrom?: string;
  validTo?: string;
  fingerprint?: string;
  error?: string;
}

/**
 * Retrieves the IP address for a given hostname.
 * @param hostname The hostname to resolve.
 * @returns A promise that resolves to the IP address or null if an error occurs.
 */
export async function getIpAddress(hostname: string): Promise<string | null> {
  try {
    const { address } = await lookup(hostname);
    return address;
  } catch (error: any) {
    console.warn(`[NetworkInfoService] Failed to resolve IP for ${hostname}:`, error.message);
    return null;
  }
}

/**
 * Retrieves SSL certificate information for a given hostname.
 * @param hostname The hostname to check.
 * @returns A promise that resolves to SslCertificateInfo or null if an error occurs or not applicable.
 */
export async function getSslCertificateInfo(hostname: string): Promise<SslCertificateInfo | null> {
  return new Promise((resolve) => {
    const options = {
      host: hostname,
      port: 443,
      rejectUnauthorized: false, // Set to true in production if you want to validate certs
      servername: hostname, // SNI
    };

    try {
      const socket = tls.connect(options, () => {
        if (!socket.authorized && socket.authorizationError) {
          console.warn(`[NetworkInfoService] SSL Authorization error for ${hostname}: ${socket.authorizationError}`);
           if (socket.authorizationError === 'CERT_HAS_EXPIRED') {
            const cert = socket.getPeerCertificate();
             resolve({
                error: `Certificate has expired. Valid until: ${cert?.valid_to || 'N/A'}`,
                validTo: cert?.valid_to,
                subject: cert?.subject ? { CN: cert.subject.CN, O: cert.subject.O } : undefined,
                issuer: cert?.issuer ? { CN: cert.issuer.CN, O: cert.issuer.O } : undefined,
             });
           } else {
             resolve({ error: `SSL authorization error: ${socket.authorizationError}` });
           }
        } else if (!socket.authorized) {
           resolve({ error: 'SSL certificate is not authorized (e.g., self-signed or untrusted CA).' });
        } else {
          const cert = socket.getPeerCertificate();
          if (cert && Object.keys(cert).length > 0) {
            resolve({
              subject: cert.subject ? { CN: cert.subject.CN, O: cert.subject.O } : undefined,
              issuer: cert.issuer ? { CN: cert.issuer.CN, O: cert.issuer.O } : undefined,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              fingerprint: cert.fingerprint,
            });
          } else {
            resolve({ error: 'No SSL certificate information received.' });
          }
        }
        socket.end();
      });

      socket.on('error', (err: any) => {
        console.warn(`[NetworkInfoService] SSL socket error for ${hostname}:`, err.message);
        if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'EHOSTUNREACH') {
             resolve({ error: `Could not connect to ${hostname}:443. The host may not support HTTPS or is unreachable.` });
        } else if (err.message && err.message.includes('routines:OPENSSL_internal:WRONG_VERSION_NUMBER')) {
            resolve({ error: `The server at ${hostname}:443 might not be speaking SSL/TLS (e.g., it's an HTTP server).` });
        }
        else {
            resolve({ error: `SSL connection error: ${err.message || 'Unknown SSL error'}` });
        }
        socket.destroy();
      });

      socket.setTimeout(5000, () => {
        console.warn(`[NetworkInfoService] SSL connection timeout for ${hostname}`);
        resolve({ error: 'SSL connection timed out.' });
        socket.destroy();
      });

    } catch (error: any) {
      console.error(`[NetworkInfoService] Error in getSslCertificateInfo setup for ${hostname}:`, error.message);
      resolve({ error: `Failed to initiate SSL check: ${error.message}` });
    }
  });
}
