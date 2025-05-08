import type { SignatureDefinition } from '../signatures';

export const marketingAutomationSignatures: SignatureDefinition[] = [
  {
    name: "Mailchimp",
    weight: 0.8,
    patterns: [
      { type: "script", pattern: /cdn-images\.mailchimp\.com/i },
      { type: "script", pattern: /s3\.amazonaws\.com\/downloads\.mailchimp\.com/i },
      { type: "html", pattern: /mc-embed|eepurl\.com/i }, // Mailchimp embedded forms or links
      { type: "networkRequest", pattern: /list-manage\.com\/subscribe/i }, // Subscription endpoint
      { type: "jsGlobal", pattern: "mc4wp" } // Mailchimp for WordPress plugin global
    ]
  },
  {
    name: "Adyen",
    weight: 0.8,
    patterns: [
      { type: "script", pattern: /checkoutshopper-live\.adyen\.com/i }, // Adyen checkout script
      { type: "script", pattern: /js\.adyen\.com/i },
      { type: "html", pattern: /adyen\.com/i }, // General mention
      { type: "jsGlobal", pattern: "AdyenCheckout" }, // Adyen JS object
      { type: "networkRequest", pattern: /pal-live\.adyen\.com/i } // Adyen API endpoint
    ]
  },
  {
    name: "ActiveCampaign",
    weight: 0.8,
    patterns: [
      { type: "script", pattern: /acem\.ac\/tracking\.js/i }, // ActiveCampaign tracking script
      { type: "script", pattern: /activehosted\.com/i },
      { type: "networkRequest", pattern: /activehosted\.com|acem\.ac/i },
      { type: "html", pattern: /activecampaign/i} // General keyword
    ]
  }
  // HubSpot, Marketo, Pardot etc.
];
