/**
 * Browser guard policy: what may be pasted or sent into AI chat websites (ChatGPT, Claude, Gemini, Copilot...).
 * The Heimdall extension classifies the text on the computer itself and sends only the kinds it found (never the text):
 *   restricted    passwords, API keys and tokens, private keys, payment card numbers      -> never
 *   confidential  lists of personal details (many emails or phone numbers), "confidential" documents -> ask an admin first
 *   public/internal  everything else                                                        -> at once
 */
import type { PolicyDocument } from "./policy.js";

export const AI_CHAT_DOMAINS = [
  "chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com", "www.perplexity.ai", "perplexity.ai",
  "poe.com", "chat.deepseek.com", "grok.com", "chat.mistral.ai", "www.meta.ai", "huggingface.co", "aistudio.google.com", "notebooklm.google.com",
];

export const BROWSER_POLICY_NAME = "Browser guard (automatic)";

export const BROWSER_POLICY: PolicyDocument = {
  schema_version: 1,
  description: "What can be pasted, typed or uploaded into AI chat websites. Never: passwords, keys, tokens, private keys and card numbers. Ask first: lists of personal details and documents marked confidential. Everything else goes through at once.",
  rules: [
    { id: "never-share-secrets", description: "Passwords, API keys, tokens, private keys and payment card numbers never go into AI chats.", effect: "deny", match: { tools: ["browser"], operations: ["external_transfer"], data_classifications: ["restricted"] } },
    { id: "ask-before-sharing-personal-data", description: "Lists of personal details and documents marked confidential.", effect: "require_approval", match: { tools: ["browser"], operations: ["external_transfer"], data_classifications: ["confidential"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "everyday-ai-chats", description: "Ordinary questions and text to AI chat websites.", effect: "allow", match: { tools: ["browser"], operations: ["external_transfer"], destination_domains: AI_CHAT_DOMAINS } },
  ],
};
