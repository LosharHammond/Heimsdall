-- Enterprise sign-in: MFA (authenticator app + recovery codes), single sign-on (Google, Kenuxa Accounts, per-organization OIDC),
-- two more roles (approver, auditor), organization security settings and richer sessions.

-- Accounts created by single sign-on have no password.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Sessions: how the person signed in, whether a second factor was used, and enough to show "where you are signed in".
ALTER TABLE sessions ADD COLUMN stage text NOT NULL DEFAULT 'active' CHECK (stage IN ('active', 'mfa_pending'));
ALTER TABLE sessions ADD COLUMN auth_method text NOT NULL DEFAULT 'password' CHECK (auth_method IN ('password', 'google', 'kenuxa', 'oidc'));
ALTER TABLE sessions ADD COLUMN sso_org_id uuid REFERENCES organizations (id) ON DELETE SET NULL;
ALTER TABLE sessions ADD COLUMN mfa_verified boolean NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN mfa_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN ip text;
ALTER TABLE sessions ADD COLUMN user_agent text;
ALTER TABLE sessions ADD COLUMN last_seen_at timestamptz;

-- Authenticator-app (TOTP) secret, encrypted at rest with AUTH_ENCRYPTION_KEY. enabled_at is null until the first code is confirmed.
CREATE TABLE user_mfa (
  user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  secret_enc text NOT NULL,
  enabled_at timestamptz,
  last_used_step bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mfa_recovery_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mfa_recovery_codes_user_idx ON mfa_recovery_codes (user_id);

-- External identities linked to a user (one per provider subject).
CREATE TABLE user_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider text NOT NULL,            -- 'google', 'kenuxa' or 'oidc:<org id>'
  subject text NOT NULL,
  email text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  UNIQUE (provider, subject)
);
CREATE INDEX user_identities_user_idx ON user_identities (user_id);

-- Organization security settings.
ALTER TABLE organizations ADD COLUMN require_mfa boolean NOT NULL DEFAULT false;
ALTER TABLE organizations ADD COLUMN sso_enforced boolean NOT NULL DEFAULT false;

-- Per-organization OIDC single sign-on (Okta, Microsoft Entra ID, Google Workspace, Kenuxa Accounts via OIDC, ...).
CREATE TABLE org_sso_configs (
  org_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  issuer text NOT NULL,
  client_id text NOT NULL,
  client_secret_enc text NOT NULL,
  allowed_domains text[] NOT NULL,
  default_role text NOT NULL DEFAULT 'viewer' CHECK (default_role IN ('viewer', 'auditor', 'approver', 'admin')),
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- One row per sign-in started with an identity provider: state, nonce and PKCE verifier, single use, short-lived.
CREATE TABLE sso_login_states (
  state_hash text PRIMARY KEY,
  provider text NOT NULL,
  org_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
  nonce text NOT NULL,
  code_verifier_enc text NOT NULL,
  return_to text NOT NULL DEFAULT '/',
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sso_login_states_expires_idx ON sso_login_states (expires_at);

-- Two more roles.
--   approver: everything a viewer can, plus decide approvals and handle alerts.
--   auditor:  everything a viewer can, plus read the audit log.
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check CHECK (role IN ('owner', 'admin', 'approver', 'auditor', 'viewer'));

-- Email domains an organization has proved it controls (DNS TXT record). Single sign-on may only use verified domains, so no
-- organization can claim someone else's addresses. A domain can be verified by one organization at a time.
CREATE TABLE org_domains (
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  domain text NOT NULL CHECK (domain = lower(domain)),
  token text NOT NULL,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, domain)
);
CREATE UNIQUE INDEX org_domains_verified_key ON org_domains (domain) WHERE verified_at IS NOT NULL;
