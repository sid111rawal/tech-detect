import type { SignatureDefinition } from '../signatures';

export const programmingLanguagesSignatures: SignatureDefinition[] = [
  {
    name: "PHP",
    weight: 0.8,
    patterns: [
      { type: "header", pattern: "x-powered-by", value: /php/i },
      { type: "cookie", pattern: /PHPSESSID/i },
      { type: "filePath", pattern: /\.php(?:\?|$)/i, weight: 0.6 } // .php extension in URL
    ]
  },
  {
    name: "Ruby",
    weight: 0.8,
    patterns: [
      { type: "header", pattern: "server", value: /Phusion Passenger/i },
      { type: "header", pattern: "x-powered-by", value: /ruby/i }, // Less common
      { type: "cookie", pattern: /_session_id/i } // Common in Rails
    ]
  },
  {
    name: "Python",
    weight: 0.8,
    patterns: [
      { type: "header", pattern: "server", value: /Python/i }, // e.g. Gunicorn, uWSGI can expose this
      { type: "header", pattern: "x-powered-by", value: /python/i },
      { type: "cookie", pattern: /csrftoken/i }, // Django CSRF cookie
      { type: "cookie", pattern: /sessionid/i } // Django session cookie (can be generic)
    ]
  }
  // ASP.NET, Java (via JServSessionID, x-powered-by: Servlet), etc.
];
