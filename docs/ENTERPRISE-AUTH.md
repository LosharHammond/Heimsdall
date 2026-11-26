# Enterprise sign-in

How people sign in to the Heimdall dashboard, how an organization controls it, and how to set each provider up.
Agent API keys (`/v1`) are unchanged: this is about humans.

## What exists

| Feature | What it does |
| --- | --- |
| **Email and password** | As before (scrypt hashes). Accounts created by single sign-on have no password. |
| **Continue with Google** | OpenID Connect with PKCE. Shown when `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set. |
| **Continue with Kenuxa Account** | "Sign in with Kenuxa" through Kenuxa Accounts (same flow Bask uses). Shown when the three `KENUXA_*` settings are set. |
| **Organization single sign-on** | Any OpenID Connect provider (Okta, Microsoft Entra ID, Google Workspace, Auth0, Keycloak), configured per organization by an owner. People type their work email and are sent to their company's sign-in page. First-time users join with a default role. |
| **Verified email domains** | An organization proves it owns a domain with a DNS TXT record before its SSO may sign in addresses at that domain. |
| **Two-step verification** | Authenticator-app codes (TOTP, RFC 6238: any authenticator app) plus 10 single-use recovery codes. |
| **Organization rules** | Owners can require two-step verification and/or require single sign-on for everyone in the organization. |
| **Roles** | Owner, Administrator, **Approver** (new: decides approvals, handles alerts), **Auditor** (new: reads the audit log), Viewer. |
| **Sessions** | Each person sees where they are signed in (browser, IP, how, whether two-step was used) and can sign out other devices. |

## How sign-in works

1. **First factor**: a password, or an identity provider (Google, Kenuxa, organization SSO).
2. **Second factor**, only if the person has turned on two-step verification: a 6-digit code or a recovery code. Until then
   the browser holds a 10-minute "pending" session that can do nothing except submit a code. Five wrong codes end it.
   An identity provider that reports MFA in the ID token (`amr` contains `mfa`, `otp`, `hwk`, ...) counts as the second factor.
3. **Organization rules** are checked on every request into an organization (the single `requireRole` chokepoint):
   - *Require two-step verification*: a session that has not passed a second factor gets `403 MFA_REQUIRED`. The dashboard
     asks for a code (step-up) or sends the person to Security to turn it on. An owner can only switch this on after doing
     it themselves, and nobody in the organization can turn their own two-step verification off while it is required.
   - *Require single sign-on*: a session not created by this organization's provider gets `403 SSO_REQUIRED`.
     **Owners are exempt** (break-glass), so a broken identity provider cannot lock the organization out.

### Account linking (one person, several ways in)

1. A known provider identity (`provider`, `subject`) signs in as its user.
2. Otherwise, a **verified** email that matches an existing account links to it (audited as `user.identity_linked`).
   Google must say `email_verified`; Kenuxa only signs in confirmed accounts; organization SSO is trusted only for its
   DNS-verified domains.
3. Otherwise a new account without a password is created.

If the account has two-step verification, signing in with Google or Kenuxa still asks for the code.

### Security properties (all covered by `tests/enterprise-auth.test.ts`)

- OpenID Connect: authorization code + PKCE (S256), `state` single-use and 10-minute expiry, `nonce` checked, ID token
  signature verified against the issuer's published keys (RS256, PS256, ES256; never `none` or shared-secret algorithms),
  `iss`, `aud`/`azp` and `exp` checked, discovery document must name the configured issuer, https only.
- Kenuxa: the one-time code is redeemed with this server's PKCE verifier at the `accounts` edge function, the returned
  single-use token is redeemed with Supabase Auth to learn the confirmed account, and that Supabase session is signed out
  immediately: Heimdall keeps no Kenuxa session or refresh token.
- TOTP: ±30 s window, each 30-second code accepted once; secrets AES-256-GCM encrypted with `AUTH_ENCRYPTION_KEY`.
  Recovery codes stored as SHA-256 and consumed once.
- The pending session token is never the final session token (rotated after the second factor).
- Every change is in the audit log: sign-ins (with method and whether MFA was used), failed codes, MFA on/off, recovery
  codes regenerated, identities linked, sessions revoked, domains added/verified, SSO configured, rules changed.

## Setting up Google sign-in

1. Google Cloud Console > APIs & Services > OAuth consent screen: set it up (External, or Internal for Workspace only).
2. Credentials > Create credentials > OAuth client ID > **Web application**.
   Authorized redirect URI: `<APP_URL>/api/auth/sso/callback` (for example `https://heimdall.kenuxa.com/api/auth/sso/callback`).
3. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, restart. The button appears on the sign-in page.

## Setting up "Continue with Kenuxa Account"

1. In the Kenuxa Supabase project (the one Bask and Kenuxa Accounts share) > SQL editor, register Heimdall once:

   ```sql
   insert into public.kenuxa_apps (client_id, name, description, home_url, icon_url, redirect_uris, sort)
   values ('heimdall', 'Kenuxa Heimdall', 'AI agent permission firewall.', 'https://YOUR-HEIMDALL-ADDRESS', null,
           array['https://YOUR-HEIMDALL-ADDRESS/api/auth/sso/callback', 'http://localhost:5173/api/auth/sso/callback'], 3);
   ```
2. Set `KENUXA_ACCOUNTS_URL` (for example `https://kenuxa-accounts.vercel.app`), `KENUXA_SUPABASE_URL` and
   `KENUXA_SUPABASE_ANON_KEY` (the same public values Bask uses), restart.
3. Check: Sign in > Continue with Kenuxa Account > sign in at Kenuxa Accounts > you return to Heimdall signed in. In Kenuxa
   Accounts > Connected apps you should see Kenuxa Heimdall.

The anon key is a public value; Heimdall never needs the Supabase service-role key.

## Setting up single sign-on for an organization (owners)

1. **Security > Email domains**: add your domain, create the TXT record shown (`_heimdall-verification.<domain>`), select Verify.
2. In your identity provider, create a web application (OIDC) with redirect URI `<APP_URL>/api/auth/sso/callback`.
3. **Security > Single sign-on**: issuer URL, client ID, client secret, the verified domains that sign in here, and the role
   for people who sign in for the first time. Saving checks the issuer's discovery document.
4. Optional: **Require single sign-on** and/or **Require two-step verification**.

Issuer examples: Okta `https://<company>.okta.com`, Microsoft Entra ID `https://login.microsoftonline.com/<tenant id>/v2.0`,
Google Workspace `https://accounts.google.com` (restrict to your domain with the verified-domain list).

## Endpoints

Public: `GET /api/auth/sso/providers`, `GET /api/auth/sso/start?provider=google|kenuxa|oidc[&email=|&org=][&return_to=/path]`
(302 to the provider), `GET /api/auth/sso/callback` (302 back to the app; errors as `/login?sso_error=CODE`),
`POST /api/auth/mfa/verify {code}|{recovery_code}` (uses the pending-session cookie).

Signed in: `GET /api/auth/mfa`, `POST /api/auth/mfa/setup {password?}`, `POST /api/auth/mfa/enable {code}`,
`POST /api/auth/mfa/step-up {code}|{recovery_code}`, `POST /api/auth/mfa/recovery-codes {password?, code}`,
`POST /api/auth/mfa/disable {password?, code}`, `GET /api/auth/sessions`, `DELETE /api/auth/sessions/:id`,
`POST /api/auth/sessions/revoke-others`.

Organization (owner to change, members to read): `GET|PATCH /api/orgs/:id/security {require_mfa?, sso_enforced?}`,
`PUT|DELETE /api/orgs/:id/sso`, `GET|POST /api/orgs/:id/domains`, `POST /api/orgs/:id/domains/:domain/verify`,
`DELETE /api/orgs/:id/domains/:domain`.

## Not built yet

- SAML 2.0 (most enterprise providers also offer OIDC, which is supported). SCIM user provisioning.
- Passkeys / security keys (WebAuthn) as a second factor.
- Email-based password reset and invitations (needs an email provider).
- Group-to-role mapping from the identity provider (everyone from SSO gets the default role; owners change roles).
- Verified against fakes, not live providers: the Google and Kenuxa flows are tested end to end against stand-ins that sign
  real tokens and check PKCE. Do the checks in "Setting up" once with your real Google client and Kenuxa project.
