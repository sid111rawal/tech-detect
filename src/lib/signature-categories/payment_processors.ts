import type { SignatureDefinition } from '../signatures';

export const paymentProcessorsSignatures: SignatureDefinition[] = [
  {
    name: "Stripe",
    weight: 0.95,
    patterns: [
      { type: "script", pattern: /js\.stripe\.com/i, weight: 0.9 },
      { type: "cookie", pattern: /__stripe_mid/, weight: 0.7 },
      { type: "cookie", pattern: /__stripe_sid/, weight: 0.7 },
      { type: "jsGlobal", pattern: "Stripe", weight: 0.9 },
      { type: "networkRequest", pattern: /api\.stripe\.com/i, weight: 0.8 },
      { type: "html", pattern: /data-stripe/i, weight: 0.7 }
    ]
  },
  {
    name: "PayPal",
    weight: 0.9,
    patterns: [
      { type: "script", pattern: /paypal\.com\/sdk/i },
      { type: "script", pattern: /paypalobjects\.com/i },
      { type: "jsGlobal", pattern: "paypal", weight: 0.9 },
      { type: "networkRequest", pattern: /\.paypal\.com/i, weight: 0.8 },
      { type: "html", pattern: /data-paypal/i, weight: 0.6 },
      { type: "cookie", pattern: /paypal/i, weight: 0.6 },
      { type: "html", pattern: /paypalcheckout/i, weight: 0.6 }
    ]
  },
  {
    name: "BitPay",
    weight: 0.9,
    patterns: [
      { type: "script", pattern: /bitpay\.com\/bitpay\.js/i },
      { type: "script", pattern: /bitpay\.com\/bitpay\.min\.js/i },
      { type: "html", pattern: /data-bitpay/i },
      { type: "networkRequest", pattern: /bitpay\.com\/api/i },
      { type: "jsGlobal", pattern: "bitpay" }
    ]
  }
];
