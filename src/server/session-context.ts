import { AsyncLocalStorage } from "node:async_hooks";

/** How the current dashboard request was authenticated. Set once per request by the session middleware. */
export interface SessionInfo {
  sessionId: string;
  userId: string;
  authMethod: "password" | "google" | "kenuxa" | "oidc";
  /** True when this session passed a second factor (authenticator code, recovery code, or an identity provider that reports MFA). */
  mfaVerified: boolean;
  /** For organization SSO sessions: the organization whose identity provider signed the person in. */
  ssoOrgId: string | null;
}

const store = new AsyncLocalStorage<SessionInfo>();
export const runWithSession = <T>(s: SessionInfo, fn: () => Promise<T>) => store.run(s, fn);
export const currentSession = (): SessionInfo | undefined => store.getStore();
