import type { SignatureDefinition } from '../signatures';

export const cookieComplianceSignatures: SignatureDefinition[] = [
  {
    name: "OneTrust",
    weight: 0.9,
    patterns: [
      { type: "script", pattern: /cdn\.cookielaw\.org/i },
      { type: "script", pattern: /optanon/i },
      { type: "cookie", pattern: /OptanonConsent/i },
      { type: "cookie", pattern: /OptanonAlertBoxClosed/i },
      { type: "jsGlobal", pattern: "OneTrust" },
      { type: "jsGlobal", pattern: "Optanon" },
      { type: "html", pattern: /onetrust/i }
    ]
  }
];
